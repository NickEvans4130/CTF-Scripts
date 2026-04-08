#!/usr/bin/env python3
"""
RSA partial key reconstruction.
When the low-order bits of d are known (e.g. from a side-channel leak),
this script brute-forces the factor p using the Boneh-Durfee / Heninger-Shacham
bit-by-bit approach.

Works for standard RSA where e is small (e.g. e=3 or e=65537) and
roughly half or more of the bits of d are known.
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
        raise ValueError("No modular inverse")
    return x % m


def recover_p_from_d_lsb(n: int, e: int, d_low: int, known_bits: int) -> int | None:
    """
    Heninger-Shacham bit-by-bit reconstruction.
    Given the low `known_bits` bits of d, recover p.

    Relation: e*d ≡ 1 (mod (p-1)(q-1))
    => e*d = k*(p-1)*(q-1) + 1 for some integer k.

    We iterate over candidate values of k and use the low bits
    of d to constrain and find p, q.
    """
    nbits = n.bit_length()
    d_mask = (1 << known_bits) - 1

    for k in range(1, e + 1):
        # e*d ≡ 1 (mod phi) => e*d_low ≡ 1 + k*(p+q-1) (mod 2^known_bits)
        # Simplified: try each k, reconstruct p bit by bit
        # For each bit position i, determine the i-th bit of p
        p_low = 1  # p is always odd, bit 0 = 1
        q_low = 1

        for bit in range(1, known_bits):
            mask = (1 << (bit + 1))
            # ed = k*phi + 1, phi = (p-1)*(q-1) = n - p - q + 1
            # => ed ≡ k*(n - p - q + 1) + 1 (mod 2^(bit+1))
            # We try both choices for bit `bit` of p
            for p_bit in range(2):
                p_candidate = p_low | (p_bit << bit)
                # q_low from p_low: p*q = n mod 2^(bit+1)
                # => q = n * modinv(p, 2^(bit+1)) mod 2^(bit+1)
                try:
                    p_inv = modinv(p_candidate, mask)
                    q_candidate = (n * p_inv) % mask

                    phi_low = (n - p_candidate - q_candidate + 1) % mask
                    lhs = (e * d_low) % mask
                    rhs = (k * phi_low + 1) % mask

                    if lhs == rhs:
                        p_low = p_candidate
                        q_low = q_candidate
                        break
                except ValueError:
                    continue

        # Try to complete p from p_low
        p_candidate = p_low
        if n % p_candidate == 0 and 1 < p_candidate < n:
            return p_candidate

    return None


def main():
    parser = argparse.ArgumentParser(description="RSA partial key reconstruction from known d LSBs")
    parser.add_argument("--n", required=True, help="RSA modulus N")
    parser.add_argument("--e", required=True, help="Public exponent e")
    parser.add_argument("--d-partial", required=True, dest="d_partial",
                        help="Known low-order bits of d (integer value)")
    parser.add_argument("--known-bits", type=int, required=True, dest="known_bits",
                        help="How many LSBs of d are known")
    parser.add_argument("--c", help="Ciphertext to decrypt (optional)")
    args = parser.parse_args()

    n         = int(args.n,         0)
    e         = int(args.e,         0)
    d_low     = int(args.d_partial, 0)
    known_bits = args.known_bits
    c         = int(args.c, 0) if args.c else None

    print(f"[*] N ({n.bit_length()} bits)")
    print(f"[*] e = {e}")
    print(f"[*] Known LSBs of d: {d_low} ({known_bits} bits)")

    p = recover_p_from_d_lsb(n, e, d_low, known_bits)
    if p is None:
        print("[-] Could not recover p. More known bits may be required (typically >= N/2 bits).")
        sys.exit(1)

    q = n // p
    phi = (p - 1) * (q - 1)
    d   = modinv(e, phi)

    print(f"\n[+] p = {p}")
    print(f"[+] q = {q}")
    print(f"[+] d = {d}")

    if c is not None:
        m = pow(c, d, n)
        print(f"\n[+] Plaintext (int): {m}")
        try:
            b = m.to_bytes((m.bit_length() + 7) // 8, 'big')
            print(f"[+] Plaintext: {b.decode('utf-8', errors='replace')}")
        except Exception:
            pass


if __name__ == "__main__":
    main()
