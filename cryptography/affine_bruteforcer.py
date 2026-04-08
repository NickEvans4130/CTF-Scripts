#!/usr/bin/env python3
"""
Affine cipher brute-forcer.
E(x) = (a*x + b) mod m  where gcd(a, m) = 1.
"""

import argparse
import math
import string
from pathlib import Path

EN_FREQ = {
    'E': 12.70, 'T': 9.06, 'A': 8.17, 'O': 7.51, 'I': 6.97, 'N': 6.75,
    'S': 6.33, 'H': 6.09, 'R': 5.99, 'D': 4.25, 'L': 4.03, 'C': 2.78,
    'U': 2.76, 'M': 2.41, 'W': 2.36, 'F': 2.23, 'G': 2.02, 'Y': 1.97,
    'P': 1.93, 'B': 1.49, 'V': 0.98, 'K': 0.77,
}


def score(text: str) -> float:
    alpha = [c.upper() for c in text if c.isalpha()]
    return sum(EN_FREQ.get(c, 0) for c in alpha) / max(len(alpha), 1)


def modinv(a: int, m: int) -> int:
    g, x, _ = _egcd(a, m)
    if g != 1:
        raise ValueError(f"gcd({a}, {m}) = {g} != 1")
    return x % m


def _egcd(a, b):
    if a == 0:
        return b, 0, 1
    g, x, y = _egcd(b % a, a)
    return g, y - (b // a) * x, x


def affine_decrypt(ciphertext: str, a: int, b: int, m: int = 26) -> str:
    a_inv = modinv(a, m)
    result = []
    for c in ciphertext:
        if c.isupper():
            result.append(chr((a_inv * (ord(c) - 65 - b)) % m + 65))
        elif c.islower():
            result.append(chr((a_inv * (ord(c) - 97 - b)) % m + 97))
        else:
            result.append(c)
    return ''.join(result)


def valid_a_values(m: int) -> list[int]:
    return [a for a in range(1, m) if math.gcd(a, m) == 1]


def main():
    parser = argparse.ArgumentParser(description="Affine cipher brute-forcer with frequency scoring")
    src = parser.add_mutually_exclusive_group(required=True)
    src.add_argument("ciphertext", nargs="?")
    src.add_argument("--file", help="Read ciphertext from file")
    parser.add_argument("--mod", type=int, default=26,
                        help="Alphabet size (default: 26)")
    parser.add_argument("--top", type=int, default=5, help="Show top N results (default: 5)")
    parser.add_argument("--a", type=int, help="Force specific value of a")
    parser.add_argument("--b", type=int, help="Force specific value of b")
    args = parser.parse_args()

    text = Path(args.file).read_text() if args.file else args.ciphertext
    m    = args.mod

    a_vals = [args.a] if args.a else valid_a_values(m)
    b_vals = [args.b] if args.b else range(m)

    print(f"[*] Testing {len(a_vals) * len(list(b_vals))} key combinations (a x b)...\n")

    candidates = []
    for a in a_vals:
        for b in b_vals:
            pt = affine_decrypt(text, a, b, m)
            candidates.append((score(pt), a, b, pt))

    candidates.sort(reverse=True)

    print(f"{'Score':>8}  {'a':>4}  {'b':>4}  Plaintext")
    print("-" * 72)
    for sc, a, b, pt in candidates[:args.top]:
        print(f"{sc:>8.3f}  {a:>4}  {b:>4}  {pt[:70].replace(chr(10), ' ')}")


if __name__ == "__main__":
    main()
