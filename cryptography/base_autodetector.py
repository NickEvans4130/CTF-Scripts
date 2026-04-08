#!/usr/bin/env python3
"""
Base16/32/58/62/64/85 auto-detector and decoder.
"""

import argparse
import base64
import re
import string
from pathlib import Path

try:
    import base58 as b58_lib
    BASE58_AVAILABLE = True
except ImportError:
    BASE58_AVAILABLE = False

BASE62_CHARS = string.digits + string.ascii_uppercase + string.ascii_lowercase


def try_base16(text: str) -> str | None:
    text = text.strip().upper()
    if re.fullmatch(r'[0-9A-F]+', text) and len(text) % 2 == 0:
        try:
            return bytes.fromhex(text).decode('utf-8', errors='replace')
        except Exception:
            return None
    return None


def try_base32(text: str) -> str | None:
    text = text.strip().upper()
    if re.fullmatch(r'[A-Z2-7=]+', text):
        try:
            return base64.b32decode(text).decode('utf-8', errors='replace')
        except Exception:
            return None
    return None


def try_base64(text: str) -> str | None:
    text = text.strip()
    if re.fullmatch(r'[A-Za-z0-9+/=]+', text):
        try:
            padded = text + '=' * (-len(text) % 4)
            return base64.b64decode(padded).decode('utf-8', errors='replace')
        except Exception:
            return None
    return None


def try_base64_url(text: str) -> str | None:
    text = text.strip()
    if re.fullmatch(r'[A-Za-z0-9\-_=]+', text):
        try:
            padded = text + '=' * (-len(text) % 4)
            return base64.urlsafe_b64decode(padded).decode('utf-8', errors='replace')
        except Exception:
            return None
    return None


def try_base85(text: str) -> str | None:
    text = text.strip()
    try:
        return base64.b85decode(text).decode('utf-8', errors='replace')
    except Exception:
        try:
            return base64.a85decode(text).decode('utf-8', errors='replace')
        except Exception:
            return None


def try_base58(text: str) -> str | None:
    if not BASE58_AVAILABLE:
        return None
    text = text.strip()
    b58_chars = string.digits[1:] + string.ascii_uppercase.replace('IO', '') + \
                string.ascii_lowercase.replace('l', '')
    if all(c in b58_chars for c in text):
        try:
            return b58_lib.b58decode(text).decode('utf-8', errors='replace')
        except Exception:
            return None
    return None


def try_base62(text: str) -> str | None:
    text = text.strip()
    if not all(c in BASE62_CHARS for c in text):
        return None
    try:
        n = 0
        for c in text:
            n = n * 62 + BASE62_CHARS.index(c)
        return n.to_bytes((n.bit_length() + 7) // 8, 'big').decode('utf-8', errors='replace')
    except Exception:
        return None


DECODERS = [
    ("Base16 (hex)", try_base16),
    ("Base32",       try_base32),
    ("Base64",       try_base64),
    ("Base64-URL",   try_base64_url),
    ("Base85",       try_base85),
    ("Base58",       try_base58),
    ("Base62",       try_base62),
]


def is_printable(text: str) -> bool:
    return all(c.isprintable() or c in '\n\r\t' for c in text)


def main():
    parser = argparse.ArgumentParser(description="Auto-detect and decode Base16/32/58/62/64/85 encodings")
    src = parser.add_mutually_exclusive_group(required=True)
    src.add_argument("text", nargs="?", help="Encoded string")
    src.add_argument("--file", help="Read encoded text from file")
    args = parser.parse_args()

    text = Path(args.file).read_text().strip() if args.file else args.text

    print(f"[*] Input ({len(text)} chars): {text[:80]!r}{'...' if len(text) > 80 else ''}\n")

    found = False
    for name, decoder in DECODERS:
        result = decoder(text)
        if result is not None and is_printable(result):
            print(f"[+] {name}: {result[:200]!r}")
            found = True

    if not found:
        print("[-] No valid decoding found for any supported base.")


if __name__ == "__main__":
    main()
