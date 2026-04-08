#!/usr/bin/env python3
"""
CRC32 / Adler32 preimage brute-forcer.
Finds a short string over a given charset that matches a target checksum.
"""

import argparse
import itertools
import string
import sys
import zlib

CHARSETS = {
    "digits":   string.digits,
    "lower":    string.ascii_lowercase,
    "upper":    string.ascii_uppercase,
    "alpha":    string.ascii_letters,
    "alphanum": string.ascii_letters + string.digits,
    "printable": string.printable.strip(),
}


def crc32(data: bytes) -> int:
    return zlib.crc32(data) & 0xFFFFFFFF


def adler32(data: bytes) -> int:
    return zlib.adler32(data) & 0xFFFFFFFF


def brute(target: int, algo, charset: str, min_len: int, max_len: int) -> bytes | None:
    total = 0
    for length in range(min_len, max_len + 1):
        count = len(charset) ** length
        print(f"[*] Trying length {length} ({count:,} candidates) ...", end=' ', flush=True)
        found = None
        for combo in itertools.product(charset, repeat=length):
            candidate = ''.join(combo).encode()
            if algo(candidate) == target:
                found = candidate
                break
        if found:
            print(f"FOUND")
            return found
        print(f"not found")
    return None


def main():
    parser = argparse.ArgumentParser(description="CRC32/Adler32 preimage brute-forcer")
    parser.add_argument("--algo", required=True, choices=["crc32", "adler32"],
                        help="Checksum algorithm")
    parser.add_argument("--target", required=True,
                        help="Target checksum (hex with 0x prefix or decimal)")
    parser.add_argument("--charset", default="alphanum", choices=CHARSETS.keys(),
                        help="Character set for candidates (default: alphanum)")
    parser.add_argument("--min-len", type=int, default=1, dest="min_len",
                        help="Minimum candidate length (default: 1)")
    parser.add_argument("--max-len", type=int, default=6, dest="max_len",
                        help="Maximum candidate length (default: 6)")
    args = parser.parse_args()

    target = int(args.target, 0)
    algo   = crc32 if args.algo == "crc32" else adler32
    cs     = CHARSETS[args.charset]

    print(f"[*] Target {args.algo.upper()}: 0x{target:08x} ({target})")
    print(f"[*] Charset: {args.charset!r} ({len(cs)} chars)")
    print(f"[*] Length range: {args.min_len}..{args.max_len}")
    print()

    result = brute(target, algo, cs, args.min_len, args.max_len)

    if result:
        print(f"\n[+] Preimage found: {result!r}  ({result.hex()})")
        print(f"[+] Verify: {args.algo}({result!r}) = 0x{algo(result):08x}")
    else:
        print(f"\n[-] No preimage found in charset={args.charset}, len={args.min_len}..{args.max_len}")


if __name__ == "__main__":
    main()
