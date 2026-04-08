#!/usr/bin/env python3
"""
HTTP request replay and modification proxy.
Reads raw HTTP requests from a file or stdin (Burp-style format),
replays them with optional header/body modifications, parameter
fuzzing, and response diffing.
Requires: requests
"""

import argparse
import re
import sys
from urllib.parse import urlparse, urlencode, parse_qs

try:
    import requests
    requests.packages.urllib3.disable_warnings()
except ImportError:
    print("[!] requests not installed: pip install requests", file=sys.stderr)
    sys.exit(1)


# ── Raw request parser ────────────────────────────────────────────────────────

def parse_raw_request(raw: str) -> dict:
    """
    Parse a raw HTTP request (Burp-style) into components.
    Returns dict with: method, path, http_version, host, headers, body
    """
    lines = raw.replace('\r\n', '\n').split('\n')
    if not lines:
        raise ValueError("Empty request")

    # Request line
    rl = lines[0].split(' ')
    method   = rl[0].upper()
    path     = rl[1] if len(rl) > 1 else "/"
    version  = rl[2] if len(rl) > 2 else "HTTP/1.1"

    headers = {}
    body    = ""
    i = 1
    while i < len(lines) and lines[i].strip():
        k, _, v = lines[i].partition(":")
        headers[k.strip()] = v.strip()
        i += 1

    # Body is everything after the blank line
    if i < len(lines):
        body = '\n'.join(lines[i+1:]).strip()

    host = headers.get("Host", "")
    return {
        "method":  method,
        "path":    path,
        "version": version,
        "host":    host,
        "headers": headers,
        "body":    body,
    }


def build_url(req: dict, scheme: str = "https") -> str:
    host = req["host"]
    path = req["path"]
    if not host:
        raise ValueError("No Host header in request")
    return f"{scheme}://{host}{path}"


# ── Modification helpers ──────────────────────────────────────────────────────

def apply_replacements(text: str, replacements: list[str]) -> str:
    for rep in replacements:
        old, _, new = rep.partition(":")
        text = text.replace(old, new)
    return text


def apply_header_overrides(headers: dict, overrides: list[str]) -> dict:
    h = dict(headers)
    for o in overrides:
        k, _, v = o.partition(":")
        h[k.strip()] = v.strip()
    return h


def fuzz_param(body: str, param: str, values: list[str]) -> list[tuple[str, str]]:
    """Return list of (label, modified_body) pairs for each fuzz value."""
    results = []
    parsed = parse_qs(body, keep_blank_values=True)
    for val in values:
        new_params = {k: v for k, v in parsed.items()}
        new_params[param] = [val]
        new_body = urlencode({k: v[0] for k, v in new_params.items()})
        results.append((f"{param}={val}", new_body))
    return results


# ── Request sender ────────────────────────────────────────────────────────────

def send_request(req: dict, url: str, body_override: str | None,
                 session: requests.Session, timeout: int) -> requests.Response | None:
    method  = req["method"]
    headers = {k: v for k, v in req["headers"].items()
               if k.lower() not in ("content-length", "transfer-encoding")}
    body    = body_override if body_override is not None else req["body"]

    try:
        if method == "GET":
            r = session.get(url, headers=headers, timeout=timeout,
                            verify=False, allow_redirects=False)
        elif method == "POST":
            r = session.post(url, data=body, headers=headers, timeout=timeout,
                             verify=False, allow_redirects=False)
        elif method == "PUT":
            r = session.put(url, data=body, headers=headers, timeout=timeout,
                            verify=False, allow_redirects=False)
        elif method == "PATCH":
            r = session.patch(url, data=body, headers=headers, timeout=timeout,
                              verify=False, allow_redirects=False)
        elif method == "DELETE":
            r = session.delete(url, headers=headers, timeout=timeout,
                               verify=False, allow_redirects=False)
        else:
            r = session.request(method, url, data=body, headers=headers,
                                timeout=timeout, verify=False, allow_redirects=False)
        return r
    except Exception as e:
        print(f"[!] Request error: {e}", file=sys.stderr)
        return None


def print_response(resp: requests.Response | None, label: str = "",
                   baseline: requests.Response | None = None):
    if resp is None:
        print(f"  [!] {label}: no response")
        return
    size = len(resp.content)
    diff = ""
    if baseline is not None:
        d = size - len(baseline.content)
        diff = f"  ({d:+}B)"
    marker = "[+]" if (baseline and resp.status_code != baseline.status_code) else "[-]"
    print(f"  {marker} {label:<40} {resp.status_code}  {size}B{diff}")


def main():
    parser = argparse.ArgumentParser(
        description="HTTP request replay tool (Burp-compatible raw request format)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Example:
  echo 'GET /admin HTTP/1.1\\nHost: target.com\\n\\n' | python3 request_replay_proxy.py --stdin --scheme http
  python3 request_replay_proxy.py --file req.txt --replace "user:admin" --header "Cookie: session=NEW"
        """)
    src = parser.add_mutually_exclusive_group(required=True)
    src.add_argument("--file",  help="File containing raw HTTP request(s), separated by blank lines")
    src.add_argument("--stdin", action="store_true", help="Read raw request from stdin")

    parser.add_argument("--scheme",  default="https", choices=["http", "https"])
    parser.add_argument("--replace", action="append", default=[], metavar="OLD:NEW",
                        help="String replacement in URL/body (repeatable)")
    parser.add_argument("--header",  action="append", default=[], metavar="H:V",
                        help="Override/add header (repeatable)")
    parser.add_argument("--fuzz-param", dest="fuzz_param",
                        help="Body parameter to fuzz")
    parser.add_argument("--fuzz-values", dest="fuzz_values", default="",
                        help="Comma-separated values for --fuzz-param")
    parser.add_argument("--repeat",  type=int, default=1,
                        help="Repeat each request N times (default: 1)")
    parser.add_argument("--timeout", type=int, default=10)
    parser.add_argument("--dump-response", action="store_true", dest="dump",
                        help="Print full response body for each request")
    args = parser.parse_args()

    # Read raw request
    if args.stdin:
        raw = sys.stdin.read()
    else:
        with open(args.file) as f:
            raw = f.read()

    # Support multiple requests separated by double newlines
    raw_requests = [r.strip() for r in re.split(r'\n{3,}', raw) if r.strip()]
    print(f"[*] Loaded {len(raw_requests)} request(s)")

    session = requests.Session()
    session.headers["User-Agent"] = "Mozilla/5.0 (CTF-Replay)"

    for idx, raw_req in enumerate(raw_requests, 1):
        print(f"\n[*] Request #{idx}")
        try:
            req = parse_raw_request(raw_req)
        except Exception as e:
            print(f"[!] Parse error: {e}")
            continue

        # Apply modifications
        req["headers"] = apply_header_overrides(req["headers"], args.header)
        req["body"]    = apply_replacements(req["body"], args.replace)
        req["path"]    = apply_replacements(req["path"], args.replace)
        url            = build_url(req, args.scheme)

        print(f"    {req['method']} {url}")
        if req["body"]:
            print(f"    Body: {req['body'][:100]!r}")

        # Baseline send
        baseline = None
        for n in range(args.repeat):
            resp = send_request(req, url, None, session, args.timeout)
            if n == 0:
                baseline = resp
                print_response(resp, f"replay #{n+1}")
            else:
                print_response(resp, f"replay #{n+1}", baseline)
            if args.dump and resp:
                print(f"\n--- Response body ---\n{resp.text[:1000]}\n---")

        # Fuzzing
        if args.fuzz_param and args.fuzz_values:
            values = [v.strip() for v in args.fuzz_values.split(",")]
            variants = fuzz_param(req["body"], args.fuzz_param, values)
            print(f"\n  [*] Fuzzing param {args.fuzz_param!r} with {len(values)} value(s)")
            for label, new_body in variants:
                resp = send_request(req, url, new_body, session, args.timeout)
                print_response(resp, label, baseline)
                if args.dump and resp:
                    print(f"\n--- Response body ---\n{resp.text[:1000]}\n---")


if __name__ == "__main__":
    main()
