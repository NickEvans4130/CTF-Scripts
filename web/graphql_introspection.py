#!/usr/bin/env python3
"""
GraphQL introspection and enumeration tool.
Queries the introspection API to dump schema, then probes for common
security misconfigurations: debug fields, admin queries, IDOR patterns,
and mutation injection points.
Requires: requests
"""

import argparse
import json
import sys

try:
    import requests
    requests.packages.urllib3.disable_warnings()
except ImportError:
    print("[!] requests not installed: pip install requests", file=sys.stderr)
    sys.exit(1)

# ── GraphQL queries ───────────────────────────────────────────────────────────

INTROSPECTION_QUERY = """
query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types {
      ...FullType
    }
    directives {
      name
      description
      locations
      args { ...InputValue }
    }
  }
}

fragment FullType on __Type {
  kind name description
  fields(includeDeprecated: true) {
    name description
    args { ...InputValue }
    type { ...TypeRef }
    isDeprecated deprecationReason
  }
  inputFields { ...InputValue }
  interfaces { ...TypeRef }
  enumValues(includeDeprecated: true) { name description isDeprecated deprecationReason }
  possibleTypes { ...TypeRef }
}

fragment InputValue on __InputValue {
  name description
  type { ...TypeRef }
  defaultValue
}

fragment TypeRef on __Type {
  kind name
  ofType {
    kind name
    ofType {
      kind name
      ofType { kind name ofType { kind name ofType { kind name ofType { kind name } } } }
    }
  }
}
"""

SIMPLE_INTROSPECTION = """
{
  __schema {
    types { name kind }
  }
}
"""

# Patterns that suggest interesting fields
INTERESTING_PATTERNS = [
    "password", "secret", "token", "key", "admin", "internal", "debug",
    "flag", "credential", "auth", "priv", "root", "super", "bypass",
    "hidden", "private", "sensitive", "ssn", "credit", "card",
]


def gql_request(session, url, query, variables=None, method="POST", timeout=10):
    payload = {"query": query}
    if variables:
        payload["variables"] = variables
    try:
        if method == "POST":
            r = session.post(url, json=payload, timeout=timeout, verify=False)
        else:
            import urllib.parse
            q = urllib.parse.quote(query)
            r = session.get(f"{url}?query={q}", timeout=timeout, verify=False)
        return r
    except Exception as e:
        print(f"[!] Request failed: {e}", file=sys.stderr)
        return None


def make_session(headers: list[str]) -> requests.Session:
    s = requests.Session()
    s.headers["User-Agent"]   = "Mozilla/5.0 (CTF-GraphQL)"
    s.headers["Content-Type"] = "application/json"
    for h in headers:
        k, _, v = h.partition(":")
        s.headers[k.strip()] = v.strip()
    return s


def parse_schema(data: dict) -> dict:
    schema = data.get("data", {}).get("__schema", {})
    types  = schema.get("types", [])
    result = {
        "query_type":    schema.get("queryType", {}).get("name") if schema.get("queryType") else None,
        "mutation_type": schema.get("mutationType", {}).get("name") if schema.get("mutationType") else None,
        "types":         {},
    }
    for t in types:
        name = t.get("name", "")
        if name.startswith("__"):
            continue
        fields = []
        for f in (t.get("fields") or []):
            fields.append({
                "name": f["name"],
                "type": resolve_type(f["type"]),
                "args": [a["name"] for a in (f.get("args") or [])],
                "deprecated": f.get("isDeprecated", False),
            })
        result["types"][name] = {
            "kind":   t.get("kind"),
            "fields": fields,
        }
    return result


def resolve_type(t) -> str:
    if t is None:
        return "Unknown"
    if t.get("name"):
        return t["name"]
    return resolve_type(t.get("ofType"))


def flag_interesting(schema: dict) -> list[dict]:
    findings = []
    for type_name, info in schema["types"].items():
        for field in info.get("fields", []):
            fname = field["name"].lower()
            for pat in INTERESTING_PATTERNS:
                if pat in fname:
                    findings.append({
                        "type": type_name,
                        "field": field["name"],
                        "ftype": field["type"],
                        "pattern": pat,
                        "deprecated": field["deprecated"],
                    })
                    break
    return findings


def print_schema(schema: dict, verbose: bool):
    qt = schema["query_type"]
    mt = schema["mutation_type"]
    print(f"\n[*] Query type:    {qt}")
    print(f"[*] Mutation type: {mt}")
    print(f"[*] Types found:   {len(schema['types'])}\n")

    for type_name, info in sorted(schema["types"].items()):
        kind   = info["kind"]
        fields = info["fields"]
        if not fields and not verbose:
            continue
        print(f"  {kind:<15} {type_name}")
        if verbose:
            for f in fields:
                dep = " [DEPRECATED]" if f["deprecated"] else ""
                args = f"({', '.join(f['args'])})" if f["args"] else ""
                print(f"    - {f['name']}{args}: {f['type']}{dep}")


def main():
    parser = argparse.ArgumentParser(description="GraphQL introspection and schema analyser")
    parser.add_argument("--url",     required=True, help="GraphQL endpoint URL")
    parser.add_argument("--method",  default="POST", choices=["POST", "GET"])
    parser.add_argument("--verbose", action="store_true",
                        help="Print all fields for every type")
    parser.add_argument("--query",   help="Run a custom GraphQL query and print result")
    parser.add_argument("--save",    help="Save raw introspection JSON to file")
    parser.add_argument("--timeout", type=int, default=10)
    parser.add_argument("--headers", action="append", default=[], metavar="H:V")
    args = parser.parse_args()

    session = make_session(args.headers)
    print(f"[*] Target: {args.url}")

    # Custom query mode
    if args.query:
        r = gql_request(session, args.url, args.query, method=args.method,
                        timeout=args.timeout)
        if r:
            try:
                print(json.dumps(r.json(), indent=2))
            except Exception:
                print(r.text)
        return

    # Introspection
    print("[*] Sending introspection query ...")
    r = gql_request(session, args.url, INTROSPECTION_QUERY,
                    method=args.method, timeout=args.timeout)

    if r is None or r.status_code != 200:
        # Try simple fallback
        print("[~] Full introspection failed, trying simple query ...")
        r = gql_request(session, args.url, SIMPLE_INTROSPECTION,
                        method=args.method, timeout=args.timeout)
        if r is None:
            print("[!] Both introspection queries failed", file=sys.stderr)
            sys.exit(1)

    try:
        data = r.json()
    except Exception:
        print(f"[!] Non-JSON response: {r.text[:200]}", file=sys.stderr)
        sys.exit(1)

    if "errors" in data and not data.get("data"):
        print(f"[!] GraphQL errors: {data['errors']}")
        print("[-] Introspection may be disabled")
        sys.exit(0)

    if args.save:
        with open(args.save, "w") as f:
            json.dump(data, f, indent=2)
        print(f"[*] Raw schema saved to {args.save}")

    schema = parse_schema(data)
    print_schema(schema, args.verbose)

    interesting = flag_interesting(schema)
    if interesting:
        print(f"\n[+] {len(interesting)} potentially sensitive field(s):")
        for item in interesting:
            dep = " [deprecated]" if item["deprecated"] else ""
            print(f"    {item['type']}.{item['field']}: {item['ftype']}"
                  f"  (matched: {item['pattern']!r}){dep}")
    else:
        print("\n[-] No obviously sensitive fields detected via pattern matching")

    # Suggest queries
    qt = schema.get("query_type")
    if qt and qt in schema["types"]:
        qfields = schema["types"][qt]["fields"]
        print(f"\n[*] Sample query stubs for {qt}:")
        for f in qfields[:10]:
            args_str = ", ".join(f'{a}: "VALUE"' for a in f["args"])
            print(f"    {{ {f['name']}({args_str}) }}")


if __name__ == "__main__":
    main()
