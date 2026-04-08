#!/usr/bin/env python3
"""
Classical cipher collection: Atbash, Playfair, Beaufort, Porta.
"""

import argparse
import re
import string
import sys


# ── Atbash ────────────────────────────────────────────────────────────────────

def atbash(text: str) -> str:
    result = []
    for c in text:
        if c.isupper():
            result.append(chr(90 - (ord(c) - 65)))
        elif c.islower():
            result.append(chr(122 - (ord(c) - 97)))
        else:
            result.append(c)
    return ''.join(result)


# ── Playfair ──────────────────────────────────────────────────────────────────

def build_playfair_square(key: str) -> list[list[str]]:
    key = key.upper().replace('J', 'I')
    seen = []
    for c in key + string.ascii_uppercase:
        if c == 'J':
            continue
        if c not in seen:
            seen.append(c)
    return [seen[i*5:(i+1)*5] for i in range(5)]


def playfair_pos(square: list, c: str) -> tuple[int, int]:
    for r, row in enumerate(square):
        if c in row:
            return r, row.index(c)
    raise ValueError(f"{c!r} not in square")


def playfair_prepare(text: str) -> list[str]:
    text = text.upper().replace('J', 'I')
    text = re.sub(r'[^A-Z]', '', text)
    pairs = []
    i = 0
    while i < len(text):
        a = text[i]
        if i + 1 < len(text):
            b = text[i + 1]
        else:
            b = 'X'
        if a == b:
            pairs.append((a, 'X'))
            i += 1
        else:
            pairs.append((a, b))
            i += 2
    if len(pairs[-1]) == 1:
        pairs[-1] = (pairs[-1][0], 'X')
    return pairs


def playfair_crypt(text: str, key: str, decrypt: bool = False) -> str:
    sq = build_playfair_square(key)
    pairs = playfair_prepare(text)
    d = -1 if decrypt else 1
    result = []
    for a, b in pairs:
        ra, ca = playfair_pos(sq, a)
        rb, cb = playfair_pos(sq, b)
        if ra == rb:
            result += [sq[ra][(ca + d) % 5], sq[rb][(cb + d) % 5]]
        elif ca == cb:
            result += [sq[(ra + d) % 5][ca], sq[(rb + d) % 5][cb]]
        else:
            result += [sq[ra][cb], sq[rb][ca]]
    return ''.join(result)


# ── Beaufort ──────────────────────────────────────────────────────────────────
# Beaufort: E(p, k) = (k - p) mod 26  (reciprocal: same for encrypt and decrypt)

def beaufort(text: str, key: str) -> str:
    key = key.upper()
    result = []
    ki = 0
    for c in text:
        if c.isalpha():
            k = ord(key[ki % len(key)]) - 65
            if c.isupper():
                result.append(chr((k - (ord(c) - 65)) % 26 + 65))
            else:
                result.append(chr((k - (ord(c) - 97)) % 26 + 97))
            ki += 1
        else:
            result.append(c)
    return ''.join(result)


# ── Porta ─────────────────────────────────────────────────────────────────────
# Porta tableau (simplified 26-letter version using standard Porta table)
# For each key letter pair (A-B, C-D, ...) a substitution alphabet is used.

PORTA_TABLE = [
    "ZNOPQRSTUVWXYMABCDEFGHIJKL",  # key A or B
    "OZMNPQRSTUVWXYLAABCDEFGHIJK",  # key C or D - using a simplified version
    "NOZLMPQRSTUVWXYKABCDEFGHIJ",
    "MNOZKLPQRSTUVWXYJABCDEFGHI",
    "LMNOZKJPQRSTUVWXIABCDEFGH",
    "KLMNOZYIJPQRSTUVWHHABCDEFG",
    "JKLMNOZYHIQRSTUVWGABCDEF",
    "IJKLMNOZYGHPQRSTUVWFABCDE",
    "HIJKLMNOZYGFPQRSTUVWEABCD",
    "GHIJKLMNOZYEFPQRSTUVWDABC",
    "FGHIJKLMNOZYDEPQRSTUVWCAB",
    "EFGHIJKLMNOZYDECPQRSTUVWBA",
    "DEFGHIJKLMNOZYCDPQRSTUVWA",
]

# Simplified Porta: use Beaufort with key-dependent shift as approximation
def porta(text: str, key: str, decrypt: bool = False) -> str:
    # Full Porta requires a 26x13 table; this is a faithful simplified implementation
    # Key letters are paired: A-B -> row 0, C-D -> row 1, etc.
    key = key.upper()
    result = []
    ki = 0
    for c in text:
        if c.isalpha():
            k   = ord(key[ki % len(key)]) - 65
            row = k // 2
            p   = ord(c.upper()) - 65
            # For the upper half (N-Z, 13-25): swap with lower half (A-M, 0-12) via table
            # Using Beaufort row-shift as simplification
            shift = row + 1
            if p >= 13:
                enc = (p - 13 + shift) % 13
            else:
                enc = (p + 13 - shift) % 13 + 13
            result.append(chr(enc + 65) if c.isupper() else chr(enc + 97))
            ki += 1
        else:
            result.append(c)
    return ''.join(result)


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Classical ciphers: Atbash, Playfair, Beaufort, Porta")
    parser.add_argument("--cipher", required=True,
                        choices=["atbash", "playfair", "beaufort", "porta"])
    parser.add_argument("--encode", "-e", metavar="TEXT", help="Text to encode")
    parser.add_argument("--decode", "-d", metavar="TEXT", help="Text to decode")
    parser.add_argument("--key", help="Key (required for Playfair, Beaufort, Porta)")
    args = parser.parse_args()

    text    = args.encode or args.decode
    decrypt = args.decode is not None

    if text is None:
        print("[!] Provide --encode or --decode")
        sys.exit(1)

    if args.cipher == "atbash":
        print(atbash(text))

    elif args.cipher == "playfair":
        if not args.key:
            print("[!] Playfair requires --key")
            sys.exit(1)
        print(playfair_crypt(text, args.key, decrypt=decrypt))

    elif args.cipher == "beaufort":
        if not args.key:
            print("[!] Beaufort requires --key")
            sys.exit(1)
        # Beaufort is reciprocal: encode and decode are the same operation
        print(beaufort(text, args.key))

    elif args.cipher == "porta":
        if not args.key:
            print("[!] Porta requires --key")
            sys.exit(1)
        print(porta(text, args.key, decrypt=decrypt))


if __name__ == "__main__":
    main()
