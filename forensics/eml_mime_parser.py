#!/usr/bin/env python3
"""
EML/MIME email parser.
Extracts headers, body text, and attachments from .eml files.
No external dependencies.
"""

import argparse
import email
import email.policy
import quopri
import re
import sys
from base64 import b64decode
from pathlib import Path


# ── Header extraction ─────────────────────────────────────────────────────────

def print_headers(msg: email.message.Message) -> None:
    print("[*] Headers")
    print("=" * 60)
    important = ["From", "To", "Cc", "Subject", "Date", "Reply-To",
                 "Message-ID", "X-Originating-IP", "Return-Path"]
    for h in important:
        val = msg.get(h)
        if val:
            print(f"  {h}: {val}")

    print("\n  -- Received chain (oldest first) --")
    received = msg.get_all("Received", [])
    for i, hop in enumerate(reversed(received)):
        print(f"  Hop {i+1}: {hop.strip()}")

    # Try to extract IPs from Received headers
    ip_re = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
    ips = []
    for hop in received:
        ips.extend(ip_re.findall(hop))
    if ips:
        unique_ips = list(dict.fromkeys(ips))
        print(f"\n  IPs in Received chain: {', '.join(unique_ips)}")


# ── Body extraction ───────────────────────────────────────────────────────────

def decode_part(part: email.message.Message) -> str:
    payload = part.get_payload(decode=True)
    if payload is None:
        return ""
    charset = part.get_content_charset() or "utf-8"
    try:
        return payload.decode(charset, errors="replace")
    except (LookupError, Exception):
        return payload.decode("utf-8", errors="replace")


def print_body(msg: email.message.Message) -> None:
    print("[*] Body")
    print("=" * 60)
    if msg.is_multipart():
        for part in msg.walk():
            ct = part.get_content_type()
            if ct in ("text/plain", "text/html"):
                disp = part.get_content_disposition()
                if disp == "attachment":
                    continue
                print(f"\n  -- {ct} --")
                text = decode_part(part)
                print(text[:3000])
    else:
        text = decode_part(msg)
        print(text[:3000])


# ── Attachment extraction ─────────────────────────────────────────────────────

def extract_attachments(msg: email.message.Message, out_dir: Path) -> None:
    print("[*] Attachments")
    print("=" * 60)
    out_dir.mkdir(parents=True, exist_ok=True)
    found = 0

    for part in msg.walk():
        disp = part.get_content_disposition()
        filename = part.get_filename()

        if disp == "attachment" or filename:
            if not filename:
                ext = part.get_content_type().split("/")[-1]
                filename = f"attachment_{found}.{ext}"

            payload = part.get_payload(decode=True)
            if payload is None:
                continue

            safe_name = re.sub(r"[^\w.\-]", "_", filename)
            out_path = out_dir / safe_name
            out_path.write_bytes(payload)
            print(f"  [{found}] {filename}  ({len(payload):,} bytes) -> {out_path}")
            found += 1

    if not found:
        print("  (no attachments found)")
    else:
        print(f"\n[*] {found} attachment(s) saved to {out_dir}")


# ── SPF / DKIM / DMARC quick check ───────────────────────────────────────────

def check_auth(msg: email.message.Message) -> None:
    print("[*] Authentication Headers")
    print("=" * 60)
    auth_fields = ["Authentication-Results", "DKIM-Signature",
                   "Received-SPF", "ARC-Authentication-Results"]
    found = False
    for field in auth_fields:
        vals = msg.get_all(field, [])
        for v in vals:
            print(f"  {field}: {v.strip()}")
            found = True
    if not found:
        print("  (no authentication headers found)")


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Parse EML/MIME email files and extract headers, body, attachments")
    parser.add_argument("file", help="EML file to parse")
    parser.add_argument("--headers",     action="store_true", help="Print headers and IP trace")
    parser.add_argument("--body",        action="store_true", help="Print body text")
    parser.add_argument("--attachments", action="store_true", help="Extract attachments")
    parser.add_argument("--auth",        action="store_true", help="Show SPF/DKIM/DMARC headers")
    parser.add_argument("--all",         action="store_true", help="Run all extractions")
    parser.add_argument("--output",      default="./attachments",
                        help="Directory to save attachments (default: ./attachments)")
    args = parser.parse_args()

    path = Path(args.file)
    if not path.exists():
        print(f"[!] File not found: {path}", file=sys.stderr)
        sys.exit(1)

    raw = path.read_bytes()
    msg = email.message_from_bytes(raw, policy=email.policy.compat32)

    run_all = args.all or not any([args.headers, args.body, args.attachments, args.auth])

    if args.headers or run_all:
        print_headers(msg)
        print()
    if args.body or run_all:
        print_body(msg)
        print()
    if args.attachments or run_all:
        extract_attachments(msg, Path(args.output))
        print()
    if args.auth or run_all:
        check_auth(msg)


if __name__ == "__main__":
    main()
