#!/usr/bin/env python3
"""
RSA modulus factoring: trial division, Fermat's method, Pollard's rho.
Requires: gmpy2 (pip install gmpy2)
"""

import argparse
import math
import random
import sys

try:
    import gmpy2
    GMPY2 = True
except ImportError:
    GMPY2 = False


def isqrt(n: int) -> int:
    return int(gmpy2.isqrt(n)) if GMPY2 else math.isqrt(n)


def is_perfect_square(n: int) -> int | None:
    r = isqrt(n)
    return r if r * r == n else None


# ── Trial division ────────────────────────────────────────────────────────────

def trial_division(n: int, limit: int = 1_000_000) -> tuple[int, int] | None:
    if n % 2 == 0:
        return 2, n // 2
    p = 3
    while p <= limit and p * p <= n:
        if n % p == 0:
            return p, n // p
        p += 2
    return None


# ── Fermat factorisation ──────────────────────────────────────────────────────

def fermat(n: int, max_iter: int = 1_000_000) -> tuple[int, int] | None:
    if n % 2 == 0:
        return 2, n // 2
    a = isqrt(n) + 1
    for _ in range(max_iter):
        b2 = a * a - n
        b = is_perfect_square(b2)
        if b is not None:
            return a - b, a + b
        a += 1
    return None


# ── Pollard's rho ─────────────────────────────────────────────────────────────

def pollard_rho(n: int, max_iter: int = 1_000_000) -> int | None:
    if n % 2 == 0:
        return 2

    def f(x, c):
        return (x * x + c) % n

    for _ in range(20):  # try multiple random starts
        x = random.randint(2, n - 1)
        y = x
        c = random.randint(1, n - 1)
        d = 1
        itr = 0
        while d == 1 and itr < max_iter:
            x = f(x, c)
            y = f(f(y, c), c)
            d = math.gcd(abs(x - y), n)
            itr += 1
        if 1 < d < n:
            return d
    return None


# ── RSA decryption ────────────────────────────────────────────────────────────

def modinv(a: int, m: int) -> int:
    if GMPY2:
        return int(gmpy2.invert(a, m))
    g, x, _ = extended_gcd(a, m)
    if g != 1:
        raise ValueError("Modular inverse does not exist")
    return x % m


def extended_gcd(a: int, b: int) -> tuple[int, int, int]:
    if a == 0:
        return b, 0, 1
    g, x, y = extended_gcd(b % a, a)
    return g, y - (b // a) * x, x


def decrypt_rsa(n: int, e: int, p: int, q: int, c: int) -> int:
    phi = (p - 1) * (q - 1)
    d = modinv(e, phi)
    return pow(c, d, n)


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Factor RSA modulus N and optionally decrypt ciphertext")
    parser.add_argument("--n", required=True, help="RSA modulus N (decimal or 0x hex)")
    parser.add_argument("--e", default="65537", help="Public exponent e (default: 65537)")
    parser.add_argument("--c", help="Ciphertext to decrypt (decimal or 0x hex)")
    parser.add_argument("--method", choices=["auto", "trial", "fermat", "pollard"],
                        default="auto", help="Factoring method (default: auto)")
    args = parser.parse_args()

    n = int(args.n, 0)
    e = int(args.e, 0)
    c = int(args.c, 0) if args.c else None

    print(f"[*] N = {n}")
    print(f"[*] e = {e}")
    print(f"[*] N bit length: {n.bit_length()}")

    p = q = None

    if args.method in ("auto", "trial"):
        print("[*] Trying trial division ...")
        res = trial_division(n)
        if res:
            p, q = res
            print(f"[+] Trial division: p={p}, q={q}")

    if p is None and args.method in ("auto", "fermat"):
        print("[*] Trying Fermat factorisation ...")
        res = fermat(n)
        if res:
            p, q = res
            print(f"[+] Fermat: p={p}, q={q}")

    if p is None and args.method in ("auto", "pollard"):
        print("[*] Trying Pollard's rho ...")
        d = pollard_rho(n)
        if d:
            p, q = d, n // d
            print(f"[+] Pollard's rho: p={p}, q={q}")

    if p is None:
        print("[-] Factorisation failed. Try a larger trial limit or a different method.")
        sys.exit(1)

    assert p * q == n, "Factorisation verification failed"
    phi = (p - 1) * (q - 1)
    d = modinv(e, phi)
    print(f"[+] p   = {p}")
    print(f"[+] q   = {q}")
    print(f"[+] phi = {phi}")
    print(f"[+] d   = {d}")

    if c is not None:
        m = decrypt_rsa(n, e, p, q, c)
        print(f"\n[+] Plaintext (int): {m}")
        try:
            b = m.to_bytes((m.bit_length() + 7) // 8, 'big')
            print(f"[+] Plaintext (bytes): {b}")
            print(f"[+] Plaintext (str): {b.decode('utf-8', errors='replace')}")
        except Exception:
            pass


if __name__ == "__main__":
    main()
