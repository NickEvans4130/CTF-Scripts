#!/usr/bin/env python3
"""
RSA Wiener's attack: recovers small private exponent d via continued fractions.
Works when d < N^(1/4) / 3.
"""

import argparse
import math
import sys


def continued_fraction(num: int, den: int) -> list[int]:
    cf = []
    while den:
        cf.append(num // den)
        num, den = den, num % den
    return cf


def convergents(cf: list[int]):
    """Yield (numerator, denominator) convergents of a continued fraction."""
    n0, n1 = 0, 1
    d0, d1 = 1, 0
    for a in cf:
        n0, n1 = n1, a * n1 + n0
        d0, d1 = d1, a * d1 + d0
        yield n1, d1


def is_perfect_square(n: int) -> int | None:
    r = math.isqrt(n)
    return r if r * r == n else None


def wiener_attack(n: int, e: int) -> int | None:
    """
    Try each convergent k/d of e/N.
    For a valid d: phi = (e*d - 1) / k, and p+q = N - phi + 1,
    then check discriminant for integer p, q.
    """
    cf = continued_fraction(e, n)
    for k, d in convergents(cf):
        if k == 0:
            continue
        if (e * d - 1) % k != 0:
            continue
        phi = (e * d - 1) // k
        # p and q satisfy x^2 - (N - phi + 1)x + N = 0
        b = n - phi + 1
        discriminant = b * b - 4 * n
        if discriminant < 0:
            continue
        sqrt_disc = is_perfect_square(discriminant)
        if sqrt_disc is None:
            continue
        p = (b + sqrt_disc) // 2
        q = (b - sqrt_disc) // 2
        if p * q == n:
            return d
    return None


def main():
    parser = argparse.ArgumentParser(description="RSA Wiener's attack for small private exponent d")
    parser.add_argument("--n", required=True, help="RSA modulus N")
    parser.add_argument("--e", required=True, help="Public exponent e")
    parser.add_argument("--c", help="Ciphertext to decrypt (optional)")
    args = parser.parse_args()

    n = int(args.n, 0)
    e = int(args.e, 0)
    c = int(args.c, 0) if args.c else None

    print(f"[*] N bit length: {n.bit_length()}")
    print(f"[*] e = {e}")
    print(f"[*] Wiener bound: d < N^(1/4) / 3 ≈ {int(n**(0.25) // 3)}")

    d = wiener_attack(n, e)
    if d is None:
        print("[-] Wiener's attack failed (d may be too large or attack conditions not met)")
        sys.exit(1)

    print(f"[+] d = {d}")

    if c is not None:
        m = pow(c, d, n)
        print(f"\n[+] Plaintext (int): {m}")
        try:
            b = m.to_bytes((m.bit_length() + 7) // 8, 'big')
            print(f"[+] Plaintext (bytes): {b}")
            print(f"[+] Plaintext (str): {b.decode('utf-8', errors='replace')}")
        except Exception:
            pass


if __name__ == "__main__":
    main()
