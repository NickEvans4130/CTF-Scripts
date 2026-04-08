#!/usr/bin/env python3
"""
Bacon cipher encoder and decoder.
Supports the 24-letter (I=J, U=V) and 26-letter alphabets,
and custom symbol pairs (e.g. A/B, 0/1, uppercase/lowercase).
"""

import argparse
import sys

# 24-letter Bacon (I=J, U=V) - A=AAAAA ... Z=BABBB
BACON_24 = {
    'A': 'AAAAA', 'B': 'AAAAB', 'C': 'AAABA', 'D': 'AAABB', 'E': 'AABAA',
    'F': 'AABAB', 'G': 'AABBA', 'H': 'AABBB', 'I': 'ABAAA', 'J': 'ABAAA',
    'K': 'ABAAB', 'L': 'ABABA', 'M': 'ABABB', 'N': 'ABBAA', 'O': 'ABBAB',
    'P': 'ABBBA', 'Q': 'ABBBB', 'R': 'BAAAA', 'S': 'BAAAB', 'T': 'BAABA',
    'U': 'BAABB', 'V': 'BAABB', 'W': 'BABAA', 'X': 'BABAB', 'Y': 'BABBA',
    'Z': 'BABBB',
}

# 26-letter (unique code for every letter)
BACON_26 = {chr(65 + i): format(i, '05b').replace('0', 'A').replace('1', 'B')
            for i in range(26)}

BACON_24_INV = {}
for ch, code in BACON_24.items():
    BACON_24_INV.setdefault(code, ch)  # first mapping wins (I before J, U before V)

BACON_26_INV = {v: k for k, v in BACON_26.items()}


def normalise_symbols(text: str, sym0: str, sym1: str) -> str:
    """Replace custom symbols with A/B."""
    return text.replace(sym0, 'A').replace(sym1, 'B')


def substitute_symbols(text: str, sym0: str, sym1: str) -> str:
    """Replace A/B with custom symbols."""
    return text.replace('A', sym0).replace('B', sym1)


def encode(plaintext: str, variant: str = '26', sym0: str = 'A', sym1: str = 'B') -> str:
    table = BACON_24 if variant == '24' else BACON_26
    result = []
    for ch in plaintext.upper():
        if ch.isalpha():
            code = table.get(ch, '?????')
            result.append(substitute_symbols(code, sym0, sym1))
        elif ch == ' ':
            result.append(' ')
    return ' '.join(result).strip() if sym0 in ('A', 'B') else ''.join(result)


def decode(ciphertext: str, variant: str = '26', sym0: str = 'A', sym1: str = 'B') -> str:
    table_inv = BACON_24_INV if variant == '24' else BACON_26_INV
    # Normalise custom symbols to A/B
    normalised = normalise_symbols(ciphertext.upper().replace(' ', ''), sym0.upper(), sym1.upper())
    result = []
    for i in range(0, len(normalised), 5):
        group = normalised[i:i + 5]
        if len(group) == 5:
            result.append(table_inv.get(group, f'[{group}]'))
    return ''.join(result)


def main():
    parser = argparse.ArgumentParser(description="Bacon cipher encoder / decoder")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--encode", "-e", metavar="TEXT", help="Text to encode")
    mode.add_argument("--decode", "-d", metavar="BACON", help="Bacon code to decode")

    parser.add_argument("--variant", choices=["24", "26"], default="26",
                        help="24-letter (I=J, U=V) or 26-letter variant (default: 26)")
    parser.add_argument("--symbols", default="AB",
                        help="Two characters for A and B (default: AB). E.g. '01' for binary.")
    args = parser.parse_args()

    if len(args.symbols) != 2:
        print("[!] --symbols must be exactly 2 characters")
        sys.exit(1)

    sym0, sym1 = args.symbols[0], args.symbols[1]

    if args.encode:
        result = encode(args.encode, args.variant, sym0, sym1)
        print(result)
    else:
        result = decode(args.decode, args.variant, sym0, sym1)
        print(result)


if __name__ == "__main__":
    main()
