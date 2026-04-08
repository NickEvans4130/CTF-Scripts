#!/usr/bin/env python3
"""
HTTP parameter pollution tester.
Sends duplicate parameters with different values and checks how the server resolves them.
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


def make_session(headers: list[str]) -> requests.Session:
    s = requests.Session()
    s.headers["User-Agent"] = "Mozilla/5.0 (CTF-HPP)"
    for h in headers:
        k, _, v = h.partition(":")
        s.headers[k.strip()] = v.strip()
    return s


def send_get_polluted(session, url, param, values, extra_params, timeout):
    """Build a GET request with duplicate parameters by constructing the query string manually."""
    qs_parts = [f"{k}={v}" for k, v in extra_params.items()]
    for v in values:
        qs_parts.append(f"{param}={v}")
    qs = "&".join(qs_parts)
    full_url = f"{url}{'&' if '?' in url else '?'}{qs}"
    try:
        return session.get(full_url, timeout=timeout, verify=False,
                           allow_redirects=True), full_url
    except Exception as e:
        return None, full_url


def send_post_polluted(session, url, param, values, extra_data, timeout):
    """Send POST with duplicate params by building raw body string."""
    parts = [f"{k}={v}" for k, v in extra_data.items()]
    for v in values:
        parts.append(f"{param}={v}")
    body = "&".join(parts)
    try:
        r = session.post(url, data=body, timeout=timeout, verify=False,
                         allow_redirects=True,
                         headers={"Content-Type": "application/x-www-form-urlencoded"})
        return r, body
    except Exception as e:
        return None, body


def compare_responses(resp_baseline, resp_polluted, label: str) -> None:
    if resp_baseline is None or resp_polluted is None:
        print(f"  {label}: request failed")
        return

    same_status = resp_baseline.status_code == resp_polluted.status_code
    size_diff   = len(resp_polluted.content) - len(resp_baseline.content)
    body_match  = resp_baseline.text[:200] == resp_polluted.text[:200]

    print(f"\n  [{label}]")
    print(f"    Baseline:  status={resp_baseline.status_code}  size={len(resp_baseline.content)}B")
    print(f"    Polluted:  status={resp_polluted.status_code}  size={len(resp_polluted.content)}B  diff={size_diff:+}B")
    if not same_status:
        print(f"    [!] STATUS CODE CHANGED: {resp_baseline.status_code} -> {resp_polluted.status_code}")
    if not body_match:
        print(f"    [!] RESPONSE BODY DIFFERS (first 200 chars)")
        print(f"        Baseline: {resp_baseline.text[:100]!r}")
        print(f"        Polluted: {resp_polluted.text[:100]!r}")
    if size_diff > 50:
        print(f"    [!] SIGNIFICANT SIZE DIFFERENCE: {size_diff:+}B")


def parse_extra(data_str: str) -> dict:
    if not data_str:
        return {}
    result = {}
    for part in data_str.split("&"):
        k, _, v = part.partition("=")
        result[k] = v
    return result


def main():
    parser = argparse.ArgumentParser(description="HTTP parameter pollution tester")
    parser.add_argument("--url",    required=True, help="Target URL")
    parser.add_argument("--param",  required=True, help="Parameter to pollute")
    parser.add_argument("--values", required=True,
                        help="Comma-separated values to send as duplicates, e.g. 'user,admin'")
    parser.add_argument("--method", default="GET", choices=["GET", "POST"])
    parser.add_argument("--data",   default="",
                        help="Additional parameters (key=val&key2=val2)")
    parser.add_argument("--timeout", type=int, default=10)
    parser.add_argument("--headers", action="append", default=[], metavar="H:V")
    args = parser.parse_args()

    session    = make_session(args.headers)
    values     = [v.strip() for v in args.values.split(",")]
    extra      = parse_extra(args.data)

    print(f"[*] Target:  {args.url}")
    print(f"[*] Param:   {args.param}")
    print(f"[*] Values:  {values}")
    print(f"[*] Method:  {args.method}")

    if args.method == "GET":
        # Baseline: single param with first value
        baseline, _ = send_get_polluted(session, args.url, args.param,
                                        [values[0]], extra, args.timeout)

        # Test all values duplicated together
        polluted, full_url = send_get_polluted(session, args.url, args.param,
                                               values, extra, args.timeout)
        print(f"\n[*] Polluted URL: {full_url}")
        compare_responses(baseline, polluted, f"all {len(values)} values")

        # Test each value against the baseline individually
        for v in values[1:]:
            r, _ = send_get_polluted(session, args.url, args.param, [v],
                                     extra, args.timeout)
            compare_responses(baseline, r, f"single value={v!r}")
    else:
        baseline, _ = send_post_polluted(session, args.url, args.param,
                                         [values[0]], extra, args.timeout)
        polluted, body = send_post_polluted(session, args.url, args.param,
                                            values, extra, args.timeout)
        print(f"\n[*] Polluted body: {body}")
        compare_responses(baseline, polluted, f"all {len(values)} values")

    print("\n[*] Interpretation guide:")
    print("    - Different status code    -> server uses first/last value differently")
    print("    - Different body content   -> server resolves the duplicate in a useful way")
    print("    - No difference            -> server ignores duplicates or uses first value only")


if __name__ == "__main__":
    main()
