#!/usr/bin/env python3
"""
RSA CRT fault attack.
Given a correct and a faulty RSA-CRT signature on the same message,
recovers p and q via gcd(s_good - s_bad, N).
"""

import argparse
import math
import sys


def modinv(a: int, m: int) -> int:
    def egcd(a, b):
        if a == 0:
            return b, 0, 1
        g, x, y = egcd(b % a, a)
        return g, y - (b // a) * x, x
    g, x, _ = egcd(a % m, m)
    if g != 1:
        raise ValueError("Modular inverse does not exist")
    return x % m


def main():
    parser = argparse.ArgumentParser(description="RSA CRT fault attack: recover p and q from a faulty signature")
    parser.add_argument("--n",     required=True, help="RSA modulus N")
    parser.add_argument("--e",     required=True, help="Public exponent e")
    parser.add_argument("--s-good", required=True, dest="s_good", help="Valid signature")
    parser.add_argument("--s-bad",  required=True, dest="s_bad",  help="Faulty signature")
    parser.add_argument("--m",     help="Original message integer (for verification)")
    args = parser.parse_args()

    n      = int(args.n,      0)
    e      = int(args.e,      0)
    s_good = int(args.s_good, 0)
    s_bad  = int(args.s_bad,  0)
    m      = int(args.m,      0) if args.m else None

    print(f"[*] N = {n}  (bit length: {n.bit_length()})")
    print(f"[*] e = {e}")

    # Verify the good signature
    if m is not None:
        verified = pow(s_good, e, n) == m % n
        print(f"[*] Good signature verifies: {verified}")

    diff = abs(s_good - s_bad)
    p = math.gcd(diff, n)

    if p in (0, 1, n):
        print("[-] gcd(s_good - s_bad, N) did not factor N.")
        print("    Ensure one signature is correct and one is faulty (different, non-trivial).")
        sys.exit(1)

    q = n // p
    assert p * q == n, "Sanity check failed: p * q != N"

    phi = (p - 1) * (q - 1)
    d   = modinv(e, phi)

    print(f"\n[+] p   = {p}")
    print(f"[+] q   = {q}")
    print(f"[+] phi = {phi}")
    print(f"[+] d   = {d}")

    if m is not None:
        c = pow(m, e, n)
        recovered = pow(c, d, n)
        print(f"\n[*] Verification decrypt: {recovered} == {m} -> {recovered == m}")


if __name__ == "__main__":
    main()
