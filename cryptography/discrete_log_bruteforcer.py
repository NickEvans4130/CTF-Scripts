#!/usr/bin/env python3
"""
Discrete logarithm solver: brute force and Baby-step Giant-step (BSGS).
Solves g^x ≡ h (mod p) for x.
"""

import argparse
import math
import sys


def brute_force(g: int, h: int, p: int, max_x: int) -> int | None:
    cur = 1
    for x in range(max_x + 1):
        if cur == h:
            return x
        cur = cur * g % p
    return None


def bsgs(g: int, h: int, p: int, order: int | None = None) -> int | None:
    """
    Baby-step Giant-step: O(sqrt(n)) time and space.
    Solves g^x ≡ h (mod p) for x in [0, order).
    order defaults to p-1.
    """
    n = order or (p - 1)
    m = math.isqrt(n) + 1

    # Baby steps: table[g^j mod p] = j  for j in 0..m-1
    table: dict[int, int] = {}
    gj = 1
    for j in range(m):
        table[gj] = j
        gj = gj * g % p

    # Giant step factor: g^(-m) mod p
    g_inv_m = pow(g, -m, p)

    # Giant steps: check g^(im) * h
    gamma = h
    for i in range(m + 1):
        if gamma in table:
            x = i * m + table[gamma]
            if x < n:
                return x
        gamma = gamma * g_inv_m % p

    return None


def main():
    parser = argparse.ArgumentParser(description="Discrete logarithm solver (brute force and BSGS)")
    parser.add_argument("--g", required=True, help="Generator g")
    parser.add_argument("--h", required=True, help="Target h = g^x mod p")
    parser.add_argument("--p", required=True, help="Prime modulus p")
    parser.add_argument("--order", help="Group order (default: p-1)")
    parser.add_argument("--method", choices=["bsgs", "brute", "auto"], default="auto",
                        help="Algorithm (default: auto - BSGS for large p, brute for small)")
    parser.add_argument("--max-x", type=int, default=10_000_000, dest="max_x",
                        help="Max x to try in brute-force mode (default: 10M)")
    args = parser.parse_args()

    g = int(args.g, 0)
    h = int(args.h, 0)
    p = int(args.p, 0)
    order = int(args.order, 0) if args.order else p - 1

    print(f"[*] g = {g}")
    print(f"[*] h = {h}")
    print(f"[*] p = {p}  (bit length: {p.bit_length()})")
    print(f"[*] order = {order}")

    method = args.method
    if method == "auto":
        method = "brute" if order < 10_000_000 else "bsgs"
    print(f"[*] Method: {method.upper()}")

    if method == "brute":
        x = brute_force(g, h, p, min(args.max_x, order))
    else:
        x = bsgs(g, h, p, order)

    if x is None:
        print(f"[-] Discrete log not found in [0, {order})")
        sys.exit(1)

    print(f"\n[+] x = {x}")
    print(f"[*] Verify: g^x mod p = {pow(g, x, p)} == h? {pow(g, x, p) == h}")


if __name__ == "__main__":
    main()
