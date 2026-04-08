#!/usr/bin/env python3
"""
RSA common modulus attack.
Recovers plaintext when the same message is encrypted under two different exponents
sharing the same modulus N, using the extended Euclidean algorithm.
Requires gcd(e1, e2) == 1.
"""

import argparse
import math
import sys


def extended_gcd(a: int, b: int) -> tuple[int, int, int]:
    if a == 0:
        return b, 0, 1
    g, x, y = extended_gcd(b % a, a)
    return g, y - (b // a) * x, x


def modinv(a: int, m: int) -> int:
    _, x, _ = extended_gcd(a % m, m)
    return x % m


def common_modulus_attack(n: int, e1: int, e2: int, c1: int, c2: int) -> int:
    """
    Given N, (e1, c1), (e2, c2) where c1 = m^e1 mod N and c2 = m^e2 mod N,
    recover m using the identity: a*e1 + b*e2 = gcd(e1, e2) = 1
    => m = c1^a * c2^b mod N
    """
    g = math.gcd(e1, e2)
    if g != 1:
        print(f"[!] gcd(e1, e2) = {g} != 1. Attack requires coprime exponents.", file=sys.stderr)
        if g > 1:
            print(f"    You can still recover m^{g} mod N.")

    _, a, b = extended_gcd(e1, e2)
    # a*e1 + b*e2 = 1
    # c1^a = m^(e1*a), c2^b = m^(e2*b)
    # product = m^(a*e1 + b*e2) = m^1 = m

    if a < 0:
        c1_inv = modinv(c1, n)
        m = (pow(c1_inv, -a, n) * pow(c2, b, n)) % n
    elif b < 0:
        c2_inv = modinv(c2, n)
        m = (pow(c1, a, n) * pow(c2_inv, -b, n)) % n
    else:
        m = (pow(c1, a, n) * pow(c2, b, n)) % n

    return m


def main():
    parser = argparse.ArgumentParser(description="RSA common modulus attack")
    parser.add_argument("--n",  required=True, help="Shared modulus N")
    parser.add_argument("--e1", required=True, help="First public exponent")
    parser.add_argument("--c1", required=True, help="Ciphertext encrypted with e1")
    parser.add_argument("--e2", required=True, help="Second public exponent")
    parser.add_argument("--c2", required=True, help="Ciphertext encrypted with e2")
    args = parser.parse_args()

    n  = int(args.n,  0)
    e1 = int(args.e1, 0)
    e2 = int(args.e2, 0)
    c1 = int(args.c1, 0)
    c2 = int(args.c2, 0)

    print(f"[*] N  = {n}")
    print(f"[*] e1 = {e1},  e2 = {e2}")
    print(f"[*] gcd(e1, e2) = {math.gcd(e1, e2)}")

    m = common_modulus_attack(n, e1, e2, c1, c2)
    print(f"\n[+] Plaintext (int): {m}")
    try:
        b = m.to_bytes((m.bit_length() + 7) // 8, 'big')
        print(f"[+] Plaintext (bytes): {b}")
        print(f"[+] Plaintext (str): {b.decode('utf-8', errors='replace')}")
    except Exception as ex:
        print(f"[!] Could not decode bytes: {ex}")


if __name__ == "__main__":
    main()
