#!/usr/bin/env python3
"""
Repeatedly Base64-decode a string until no further valid decoding is possible.
"""

import argparse
import base64
import re
import sys
from pathlib import Path

FLAG_RE = re.compile(r'(?:flag|ctf|htb|picoctf|thm)\{[^}]{1,200}\}', re.IGNORECASE)


def is_valid_b64(text: str) -> bool:
    text = text.strip()
    return bool(re.fullmatch(r'[A-Za-z0-9+/=\-_]+', text) and len(text) % 4 in (0, 2, 3))


def try_decode(text: str) -> bytes | None:
    text = text.strip()
    for decoder in (base64.b64decode, base64.urlsafe_b64decode):
        try:
            padded = text + '=' * (-len(text) % 4)
            result = decoder(padded)
            # Accept if result is decodable as latin-1 (bytes that make sense)
            result.decode('latin-1')
            return result
        except Exception:
            continue
    return None


def main():
    parser = argparse.ArgumentParser(description="Repeatedly Base64-decode until no further decoding is possible")
    src = parser.add_mutually_exclusive_group(required=True)
    src.add_argument("text", nargs="?", help="Base64-encoded string")
    src.add_argument("--file", help="Read encoded text from file")
    parser.add_argument("--max", type=int, default=100, help="Max decode iterations (default: 100)")
    args = parser.parse_args()

    current = Path(args.file).read_text().strip() if args.file else args.text

    print(f"[*] Input:  {current[:80]!r}{'...' if len(current) > 80 else ''}")
    print()

    for iteration in range(1, args.max + 1):
        if not is_valid_b64(current):
            print(f"[*] Stopped at iteration {iteration}: not valid Base64")
            break

        decoded = try_decode(current)
        if decoded is None:
            print(f"[*] Stopped at iteration {iteration}: decode failed")
            break

        try:
            text = decoded.decode('utf-8')
        except UnicodeDecodeError:
            try:
                text = decoded.decode('latin-1')
            except Exception:
                print(f"[*] Stopped at iteration {iteration}: binary output")
                print(f"    Hex: {decoded[:64].hex()}")
                break

        print(f"[{iteration:>3}] {text[:120]!r}")

        flag_match = FLAG_RE.search(text)
        if flag_match:
            print(f"\n[!] Flag detected: {flag_match.group()}")

        if not is_valid_b64(text):
            print(f"\n[*] Final output (not Base64):\n{text}")
            break

        current = text
    else:
        print(f"[*] Reached max iterations ({args.max}). Final value: {current[:200]!r}")


if __name__ == "__main__":
    main()
