#!/usr/bin/env python3
"""
RSA Håstad's broadcast attack.
Recovers plaintext when the same message is encrypted with a low exponent e
to e different recipients (different N, same e).
Uses Chinese Remainder Theorem then integer eth-root.
"""

import argparse
import math
import sys


def extended_gcd(a: int, b: int) -> tuple[int, int, int]:
    if a == 0:
        return b, 0, 1
    g, x, y = extended_gcd(b % a, a)
    return g, y - (b // a) * x, x


def crt(remainders: list[int], moduli: list[int]) -> int:
    """Chinese Remainder Theorem: find x s.t. x ≡ r_i (mod m_i)."""
    M = math.prod(moduli)
    x = 0
    for r, m in zip(remainders, moduli):
        Mi = M // m
        _, inv, _ = extended_gcd(Mi % m, m)
        x += r * Mi * inv
    return x % M


def iroot(n: int, k: int) -> tuple[int, bool]:
    """Integer kth root of n. Returns (root, exact)."""
    if n < 0:
        raise ValueError("n must be non-negative")
    if n == 0:
        return 0, True
    if k == 1:
        return n, True
    # Newton's method
    x = int(round(n ** (1.0 / k)))
    # Adjust around the estimate
    for candidate in range(max(0, x - 2), x + 3):
        if candidate ** k == n:
            return candidate, True
        if candidate ** k > n:
            return candidate - 1, False
    return x, x ** k == n


def main():
    parser = argparse.ArgumentParser(description="RSA Håstad broadcast attack (low public exponent)")
    parser.add_argument("--e", type=int, required=True,
                        help="Public exponent e (must equal number of (N, C) pairs)")
    parser.add_argument("--pairs", nargs="+", metavar="N,C",
                        help="Space-separated N,C pairs e.g. '3233,2790 5183,1650'")
    parser.add_argument("--file", help="File with one 'N C' pair per line")
    args = parser.parse_args()

    pairs: list[tuple[int, int]] = []
    if args.file:
        for line in open(args.file):
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            parts = line.replace(',', ' ').split()
            pairs.append((int(parts[0], 0), int(parts[1], 0)))
    elif args.pairs:
        for p in args.pairs:
            n_str, c_str = p.split(',')
            pairs.append((int(n_str, 0), int(c_str, 0)))
    else:
        print("[!] Provide --pairs or --file", file=sys.stderr)
        sys.exit(1)

    e = args.e
    if len(pairs) < e:
        print(f"[!] Need at least {e} (N, C) pairs for e={e}, got {len(pairs)}", file=sys.stderr)
        sys.exit(1)

    pairs = pairs[:e]
    moduli    = [p[0] for p in pairs]
    ciphers   = [p[1] for p in pairs]

    print(f"[*] e = {e},  using {e} ciphertext pairs")

    # CRT to get m^e mod (N1*N2*...*Ne)
    me = crt(ciphers, moduli)

    # Take eth root
    m, exact = iroot(me, e)
    if exact:
        print(f"[+] Plaintext (int): {m}")
        try:
            b = m.to_bytes((m.bit_length() + 7) // 8, 'big')
            print(f"[+] Plaintext (bytes): {b}")
            print(f"[+] Plaintext (str): {b.decode('utf-8', errors='replace')}")
        except Exception:
            pass
    else:
        print(f"[-] eth root is not exact (m^e mod product ≠ m^e over integers)")
        print(f"    Approximate root: {m}")
        print(f"    Check that all N are distinct and message has no padding.")


if __name__ == "__main__":
    main()
