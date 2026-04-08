#!/usr/bin/env python3
"""
LFSR state and feedback polynomial recovery using the Berlekamp-Massey algorithm.
Given an observed output bit sequence, recovers the minimal LFSR that produces it.
"""

import argparse
import sys
from pathlib import Path


def berlekamp_massey(sequence: list[int]) -> list[int]:
    """
    Berlekamp-Massey algorithm over GF(2).
    Returns the shortest LFSR feedback polynomial coefficients [c1, c2, ..., cL]
    such that s[n] = c1*s[n-1] XOR c2*s[n-2] XOR ... XOR cL*s[n-L].
    """
    n = len(sequence)
    C = [1]  # connection polynomial (C[0] always = 1)
    B = [1]  # previous connection polynomial
    L = 0    # current LFSR length
    m = 1    # number of steps since last length change
    b = 1    # leading coefficient of B when it was set

    for i in range(n):
        # Compute discrepancy
        d = sequence[i]
        for j in range(1, L + 1):
            if j < len(C):
                d ^= C[j] & sequence[i - j]
        d &= 1

        if d == 0:
            m += 1
        elif 2 * L <= i:
            T = C[:]
            # Extend C
            while len(C) < len(B) + m:
                C.append(0)
            for j in range(len(B)):
                C[j + m] ^= (d * pow(b, -1, 2) * B[j]) % 2
            L = i + 1 - L
            B = T
            b = d
            m = 1
        else:
            while len(C) < len(B) + m:
                C.append(0)
            for j in range(len(B)):
                C[j + m] ^= (d * pow(b, -1, 2) * B[j]) % 2
            m += 1

    return C[1:]  # return [c1, ..., cL]


def recover_initial_state(sequence: list[int], poly: list[int]) -> list[int]:
    """First L bits of the sequence are the initial state (shift register content)."""
    return sequence[:len(poly)]


def lfsr_generate(state: list[int], poly: list[int], n: int) -> list[int]:
    """Generate n bits from the LFSR with given state and feedback polynomial."""
    reg = list(state)
    L   = len(poly)
    out = []
    for _ in range(n):
        out.append(reg[-1])
        new_bit = 0
        for i, c in enumerate(poly):
            new_bit ^= c & reg[L - 1 - i]
        reg = [new_bit] + reg[:-1]
    return out


def parse_bits(s: str) -> list[int]:
    """Parse a binary string like '01101001' into a list of ints."""
    return [int(c) for c in s if c in '01']


def main():
    parser = argparse.ArgumentParser(description="LFSR recovery using Berlekamp-Massey algorithm")
    src = parser.add_mutually_exclusive_group(required=True)
    src.add_argument("--bits", help="Binary output sequence as a string of 0s and 1s")
    src.add_argument("--file", help="File containing binary sequence (0s and 1s, whitespace ignored)")
    parser.add_argument("--predict", type=int, default=0,
                        help="Predict this many future bits after recovery")
    parser.add_argument("--degree", type=int,
                        help="Force LFSR degree (skip Berlekamp-Massey, use this degree)")
    args = parser.parse_args()

    if args.file:
        raw = Path(args.file).read_text()
        sequence = parse_bits(raw)
    else:
        sequence = parse_bits(args.bits)

    print(f"[*] Input sequence ({len(sequence)} bits): {''.join(map(str, sequence[:60]))}{'...' if len(sequence) > 60 else ''}")

    if args.degree:
        L = args.degree
        state = sequence[:L]
        # Solve for polynomial from sequence
        poly_raw = berlekamp_massey(sequence)
        poly = poly_raw[:L]
        print(f"[*] Forced degree {L}, fitting polynomial ...")
    else:
        poly = berlekamp_massey(sequence)
        L    = len(poly)
        state = recover_initial_state(sequence, poly)

    print(f"\n[+] LFSR degree (L): {L}")
    print(f"[+] Feedback polynomial coefficients (c1..cL): {poly}")
    print(f"    Polynomial: s[n] = " +
          " XOR ".join(f"s[n-{i+1}]" for i, c in enumerate(poly) if c) or "0")
    print(f"[+] Initial state: {state}")

    # Verify: regenerate sequence and compare
    generated = lfsr_generate(state, poly, len(sequence))
    match = generated == sequence
    print(f"\n[*] Verification (regenerated matches input): {match}")
    if not match:
        diff = sum(a != b for a, b in zip(generated, sequence))
        print(f"    {diff}/{len(sequence)} bits differ")

    if args.predict > 0:
        # Generate from the state after consuming the known sequence
        # Advance the register by len(sequence) - L steps
        advanced = list(sequence[len(sequence) - L:])[::-1]  # last L bits as state
        future = lfsr_generate(advanced, poly, args.predict)
        print(f"\n[+] Next {args.predict} predicted bits:")
        print(''.join(map(str, future)))


if __name__ == "__main__":
    main()
