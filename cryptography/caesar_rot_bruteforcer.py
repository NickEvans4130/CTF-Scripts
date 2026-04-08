#!/usr/bin/env python3
"""
Caesar / ROT-N brute-forcer with English letter frequency analysis scoring.
"""

import argparse
import string
from pathlib import Path

EN_FREQ = {
    'E': 12.70, 'T': 9.06, 'A': 8.17, 'O': 7.51, 'I': 6.97, 'N': 6.75,
    'S': 6.33, 'H': 6.09, 'R': 5.99, 'D': 4.25, 'L': 4.03, 'C': 2.78,
    'U': 2.76, 'M': 2.41, 'W': 2.36, 'F': 2.23, 'G': 2.02, 'Y': 1.97,
    'P': 1.93, 'B': 1.49, 'V': 0.98, 'K': 0.77, 'J': 0.15, 'X': 0.15,
    'Q': 0.10, 'Z': 0.07,
}


def score(text: str) -> float:
    total = sum(1 for c in text if c.isalpha())
    if total == 0:
        return 0.0
    return sum(EN_FREQ.get(c.upper(), 0) for c in text if c.isalpha()) / total


def rotate(text: str, n: int) -> str:
    out = []
    for c in text:
        if c in string.ascii_uppercase:
            out.append(chr((ord(c) - 65 + n) % 26 + 65))
        elif c in string.ascii_lowercase:
            out.append(chr((ord(c) - 97 + n) % 26 + 97))
        else:
            out.append(c)
    return ''.join(out)


def main():
    parser = argparse.ArgumentParser(description="Brute-force Caesar/ROT-N cipher with frequency scoring")
    src = parser.add_mutually_exclusive_group(required=True)
    src.add_argument("ciphertext", nargs="?", help="Ciphertext string")
    src.add_argument("--file", help="Read ciphertext from file")
    parser.add_argument("--top", type=int, default=5, help="Show top N candidates (default: 5)")
    parser.add_argument("--rot", type=int, help="Only try this specific rotation (0-25)")
    args = parser.parse_args()

    text = Path(args.file).read_text() if args.file else args.ciphertext

    rotations = [args.rot % 26] if args.rot is not None else range(1, 26)
    candidates = sorted(
        [(score(rotate(text, n)), n, rotate(text, n)) for n in rotations],
        reverse=True
    )

    print(f"{'Rot':<6} {'Score':>7}  Plaintext")
    print("-" * 72)
    for sc, n, pt in candidates[:args.top]:
        print(f"ROT{n:<4} {sc:>7.3f}  {pt[:80].replace(chr(10), ' ')}")


if __name__ == "__main__":
    main()
