#!/usr/bin/env python3
"""
CORS misconfiguration tester.
Sends requests with various Origin headers and analyses the
Access-Control-Allow-Origin / Access-Control-Allow-Credentials
response headers for common misconfigurations.
Requires: requests
"""

import argparse
import sys
from urllib.parse import urlparse

try:
    import requests
    requests.packages.urllib3.disable_warnings()
except ImportError:
    print("[!] requests not installed: pip install requests", file=sys.stderr)
    sys.exit(1)


def make_session(headers: list[str]) -> requests.Session:
    s = requests.Session()
    s.headers["User-Agent"] = "Mozilla/5.0 (CTF-CORS)"
    for h in headers:
        k, _, v = h.partition(":")
        s.headers[k.strip()] = v.strip()
    return s


def build_test_origins(target_url: str, extra: list[str]) -> list[tuple[str, str]]:
    """Return (origin, test_label) pairs to try."""
    parsed = urlparse(target_url)
    host   = parsed.hostname or "target.com"
    scheme = parsed.scheme or "https"
    base   = f"{scheme}://{host}"

    origins = [
        ("null",                                    "null origin"),
        (f"{scheme}://evil.com",                    "arbitrary third-party"),
        (f"{scheme}://evil.{host}",                 "subdomain prefix (evil.target)"),
        (f"{scheme}://{host}.evil.com",             "domain suffix (target.evil.com)"),
        (f"{scheme}://not{host}",                   "adjacent domain"),
        (f"http://{host}",                          "HTTP downgrade (if HTTPS)"),
        (f"https://{host}",                         "HTTPS variant"),
        (f"{scheme}://{host}:8080",                 "non-standard port"),
        (f"{scheme}://sub.{host}",                  "arbitrary subdomain"),
        (f"{scheme}://{host}%60.evil.com",          "URL-encoded backtick bypass"),
        ("",                                        "empty Origin header"),
    ]
    for o in extra:
        origins.append((o, "custom"))
    return origins


def probe(session, url, method, data, origin, timeout):
    headers = {"Origin": origin} if origin else {}
    try:
        if method == "GET":
            r = session.get(url, headers=headers, timeout=timeout,
                            verify=False, allow_redirects=True)
        else:
            r = session.post(url, data=data, headers=headers,
                             timeout=timeout, verify=False, allow_redirects=True)
        return r
    except Exception:
        return None


def analyse(origin: str, label: str, resp: requests.Response) -> dict | None:
    if resp is None:
        return None

    acao  = resp.headers.get("Access-Control-Allow-Origin", "")
    acac  = resp.headers.get("Access-Control-Allow-Credentials", "")
    acam  = resp.headers.get("Access-Control-Allow-Methods", "")
    acah  = resp.headers.get("Access-Control-Allow-Headers", "")

    if not acao:
        return None  # No CORS header — not interesting

    issues = []

    if acao == "*":
        issues.append("wildcard (*) ACAO")
    elif acao == origin and origin not in ("", "null"):
        issues.append("origin reflected verbatim")
    elif acao == "null" and origin == "null":
        issues.append("null origin accepted")

    if acac.lower() == "true":
        issues.append("credentials allowed")

    dangerous = bool(issues) and ("credentials allowed" in issues or
                                  "origin reflected verbatim" in issues or
                                  "null origin accepted" in issues)

    return {
        "origin":  origin,
        "label":   label,
        "acao":    acao,
        "acac":    acac,
        "methods": acam,
        "headers": acah,
        "issues":  issues,
        "critical": dangerous,
    }


def main():
    parser = argparse.ArgumentParser(description="CORS misconfiguration tester")
    parser.add_argument("--url",    required=True, help="Target URL")
    parser.add_argument("--method", default="GET", choices=["GET", "POST"])
    parser.add_argument("--data",   default="", help="POST body (key=val&...)")
    parser.add_argument("--origin", action="append", default=[], metavar="ORIGIN",
                        help="Additional Origin values to test (repeatable)")
    parser.add_argument("--timeout", type=int, default=10)
    parser.add_argument("--headers", action="append", default=[], metavar="H:V")
    args = parser.parse_args()

    session   = make_session(args.headers)
    base_data = {}
    if args.data:
        for part in args.data.split("&"):
            k, _, v = part.partition("=")
            base_data[k] = v

    test_origins = build_test_origins(args.url, args.origin)
    print(f"[*] Target: {args.url}  ({len(test_origins)} origin probes)\n")

    findings = []
    for origin, label in test_origins:
        r = probe(session, args.url, args.method, base_data, origin, args.timeout)
        result = analyse(origin, label, r)
        if result is None:
            continue

        marker = "[+]" if result["critical"] else "[~]"
        print(f"  {marker} Origin: {origin!r:<50} [{label}]")
        print(f"      ACAO: {result['acao']}  ACAC: {result['acac'] or '(none)'}")
        if result["issues"]:
            print(f"      Issues: {', '.join(result['issues'])}")
        if result["critical"]:
            findings.append(result)

    if findings:
        print(f"\n[+] {len(findings)} exploitable CORS misconfiguration(s):")
        for f in findings:
            print(f"    origin={f['origin']!r}  issues={f['issues']}")
        print()
        print("[*] Exploitation: set Origin to the accepted value in a cross-origin")
        print("    fetch() with credentials:\"include\" to steal authenticated responses.")
    else:
        print("\n[-] No exploitable CORS misconfigurations detected")


if __name__ == "__main__":
    main()
