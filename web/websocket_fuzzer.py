#!/usr/bin/env python3
"""
WebSocket fuzzer.
Connects to a WebSocket endpoint, sends payloads, and records responses.
Supports injection testing (SQLi, SSTI, XSS, command injection) and
custom message replay.
Requires: websocket-client  (pip install websocket-client)
"""

import argparse
import json
import sys
import time

try:
    import websocket
except ImportError:
    print("[!] websocket-client not installed: pip install websocket-client", file=sys.stderr)
    sys.exit(1)

# ── Built-in fuzzing payloads ─────────────────────────────────────────────────

INJECTION_PAYLOADS = [
    # SQLi
    ("'", "SQLi single quote"),
    ('"', "SQLi double quote"),
    ("' OR '1'='1", "SQLi OR bypass"),
    ("1; DROP TABLE users--", "SQLi stacked"),
    ("' UNION SELECT 1,2,3--", "SQLi UNION"),
    # SSTI
    ("{{7*7}}", "SSTI Jinja2"),
    ("${7*7}", "SSTI expr"),
    ("<%= 7*7 %>", "SSTI ERB"),
    # XSS
    ('<script>alert(1)</script>', "XSS script tag"),
    ('"><img src=x onerror=alert(1)>', "XSS img onerror"),
    ("javascript:alert(1)", "XSS javascript:"),
    # Command injection
    ("; id", "CMDi semicolon"),
    ("| id", "CMDi pipe"),
    ("`id`", "CMDi backtick"),
    ("$(id)", "CMDi subshell"),
    # Format string
    ("%s%s%s%s", "format string"),
    ("{0}", "python format"),
    # Large / special
    ("A" * 10000, "10KB overflow"),
    ("\x00\x01\x02\x03", "binary bytes"),
    ("null", "literal null"),
    ("undefined", "undefined"),
    ("[]", "empty array"),
    ("{}", "empty object"),
    ("-1", "negative int"),
    ("9999999999999", "large int"),
]

INTERESTING_PATTERNS = [
    "error", "exception", "traceback", "syntax", "sql", "database",
    "warning", "undefined", "null", "flag{", "ctf{", "root:", "uid=",
    "49",  # 7*7 SSTI
]


def check_interesting(msg: str) -> list[str]:
    ml = msg.lower()
    return [p for p in INTERESTING_PATTERNS if p.lower() in ml]


def make_ws(url, headers: list[str], timeout: int):
    extra_headers = {}
    for h in headers:
        k, _, v = h.partition(":")
        extra_headers[k.strip()] = v.strip()
    ws = websocket.WebSocket(sslopt={"cert_reqs": 0})
    ws.connect(url, header=extra_headers, timeout=timeout)
    return ws


def send_recv(ws, message: str, recv_timeout: float = 3.0) -> str | None:
    try:
        ws.send(message)
        ws.settimeout(recv_timeout)
        return ws.recv()
    except websocket.WebSocketTimeoutException:
        return None
    except Exception as e:
        return f"[ERROR] {e}"


def wrap_payload(payload: str, template: str | None) -> str:
    """Optionally insert payload into a JSON template."""
    if template is None:
        return payload
    try:
        obj = json.loads(template)
        # Inject into every string value
        def inject(o):
            if isinstance(o, dict):
                return {k: inject(v) for k, v in o.items()}
            elif isinstance(o, list):
                return [inject(i) for i in o]
            elif isinstance(o, str):
                return payload
            return o
        return json.dumps(inject(obj))
    except json.JSONDecodeError:
        return template.replace("FUZZ", payload)


def main():
    parser = argparse.ArgumentParser(description="WebSocket fuzzer")
    parser.add_argument("--url",      required=True, help="WebSocket URL (ws:// or wss://)")
    parser.add_argument("--message",  help="Single message to send and receive")
    parser.add_argument("--fuzz",     action="store_true",
                        help="Run injection payload fuzzing")
    parser.add_argument("--template", help="JSON template with FUZZ as placeholder, "
                                           "or valid JSON where all string values are replaced")
    parser.add_argument("--messages-file", dest="msg_file",
                        help="File with one message per line to replay")
    parser.add_argument("--delay",    type=float, default=0.2,
                        help="Delay between messages in seconds (default: 0.2)")
    parser.add_argument("--recv-timeout", type=float, default=3.0, dest="recv_timeout")
    parser.add_argument("--timeout",  type=int, default=10)
    parser.add_argument("--headers",  action="append", default=[], metavar="H:V")
    args = parser.parse_args()

    print(f"[*] Connecting to {args.url} ...")
    try:
        ws = make_ws(args.url, args.headers, args.timeout)
    except Exception as e:
        print(f"[!] Connection failed: {e}", file=sys.stderr)
        sys.exit(1)
    print("[*] Connected\n")

    # Single message mode
    if args.message:
        resp = send_recv(ws, args.message, args.recv_timeout)
        print(f"[*] Sent:     {args.message!r}")
        print(f"[*] Received: {resp!r}")
        ws.close()
        return

    # File replay mode
    if args.msg_file:
        with open(args.msg_file) as f:
            messages = [l.rstrip('\n') for l in f if l.strip()]
        print(f"[*] Replaying {len(messages)} message(s) from file\n")
        for msg in messages:
            resp = send_recv(ws, msg, args.recv_timeout)
            hits = check_interesting(resp or "")
            marker = "[+]" if hits else "[-]"
            print(f"  {marker} sent={msg!r}  recv={str(resp)[:100]!r}  hits={hits}")
            time.sleep(args.delay)
        ws.close()
        return

    # Fuzz mode
    if args.fuzz:
        print(f"[*] Fuzzing with {len(INJECTION_PAYLOADS)} payloads\n")
        findings = []
        for payload, label in INJECTION_PAYLOADS:
            msg  = wrap_payload(payload, args.template)
            resp = send_recv(ws, msg, args.recv_timeout)
            hits = check_interesting(resp or "")
            if hits:
                print(f"  [+] {label:<30} hits={hits}")
                print(f"      sent={msg[:80]!r}")
                print(f"      recv={str(resp)[:150]!r}\n")
                findings.append({"label": label, "payload": payload,
                                 "response": resp, "hits": hits})
            else:
                print(f"  [-] {label:<30} recv={str(resp)[:60]!r}")
            time.sleep(args.delay)
            # Reconnect if connection dropped
            try:
                ws.ping()
            except Exception:
                try:
                    ws = make_ws(args.url, args.headers, args.timeout)
                except Exception:
                    print("[!] Reconnect failed, stopping early")
                    break

        print(f"\n[*] {len(findings)} interesting response(s)")
        for f in findings:
            print(f"    {f['label']}  ->  hits={f['hits']}")
        ws.close()
        return

    print("[!] Specify --message, --fuzz, or --messages-file")
    ws.close()


if __name__ == "__main__":
    main()
