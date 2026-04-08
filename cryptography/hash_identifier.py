#!/usr/bin/env python3
"""
Hash identifier - identifies likely hash algorithm from length and character set.
"""

import argparse
import re
import sys

# (name, length, charset_regex, hashcat_mode, notes)
SIGNATURES = [
    # MD family
    ("MD5",              32, r'^[0-9a-fA-F]+$',   0,    "Very common"),
    ("MD5(Unix)",        34, r'^\$1\$',            500,  "Unix crypt $1$"),
    ("MD4",              32, r'^[0-9a-fA-F]+$',   900,  "Windows NTLMv1"),
    ("NTLM",             32, r'^[0-9a-fA-F]+$',   1000, "Windows NTLM"),
    # SHA-1
    ("SHA-1",            40, r'^[0-9a-fA-F]+$',   100,  "Very common"),
    ("SHA-1(Django)",    50, r'^sha1\$',           124,  "Django SHA-1"),
    # SHA-2 family
    ("SHA-224",          56, r'^[0-9a-fA-F]+$',   1300, ""),
    ("SHA-256",          64, r'^[0-9a-fA-F]+$',   1400, "Very common"),
    ("SHA-384",          96, r'^[0-9a-fA-F]+$',   10800,""),
    ("SHA-512",         128, r'^[0-9a-fA-F]+$',   1700, "Very common"),
    ("SHA-512/256",      64, r'^[0-9a-fA-F]+$',   None, ""),
    # SHA-3
    ("SHA3-224",         56, r'^[0-9a-fA-F]+$',   17300,""),
    ("SHA3-256",         64, r'^[0-9a-fA-F]+$',   17400,""),
    ("SHA3-384",         96, r'^[0-9a-fA-F]+$',   17500,""),
    ("SHA3-512",        128, r'^[0-9a-fA-F]+$',   17600,""),
    # bcrypt
    ("bcrypt",           60, r'^\$2[ayb]\$',       3200, "60 chars starting $2a$/$2b$"),
    # Argon2
    ("Argon2",           None, r'^\$argon2',       None, "PHC string format"),
    # scrypt
    ("scrypt",           None, r'^\$s0\$',         None, ""),
    # PBKDF2
    ("PBKDF2-SHA256",    None, r'pbkdf2_sha256',   None, "Django/Passlib"),
    # Unix crypt
    ("DES(Unix)",        13, r'^[./a-zA-Z0-9]{13}$', 1500, "Traditional crypt(3)"),
    ("SHA-512(Unix)",    106, r'^\$6\$',           1800, "$6$ Unix crypt"),
    ("SHA-256(Unix)",    63, r'^\$5\$',            7400, "$5$ Unix crypt"),
    # MySQL
    ("MySQL3.23",        16, r'^[0-9a-fA-F]{16}$', 200, "Old MySQL"),
    ("MySQL4.1+",        41, r'^\*[0-9A-F]{40}$',  300, "MySQL 4.1 and later"),
    # CRC
    ("CRC32",            8,  r'^[0-9a-fA-F]{8}$',  None, "Checksum"),
    ("Adler32",          8,  r'^[0-9a-fA-F]{8}$',  None, "Checksum"),
    # RIPEMD
    ("RIPEMD-128",       32, r'^[0-9a-fA-F]+$',   None, ""),
    ("RIPEMD-160",       40, r'^[0-9a-fA-F]+$',   6000, ""),
    ("RIPEMD-256",       64, r'^[0-9a-fA-F]+$',   None, ""),
    ("RIPEMD-320",       80, r'^[0-9a-fA-F]+$',   None, ""),
    # Whirlpool
    ("Whirlpool",       128, r'^[0-9a-fA-F]+$',   6100, ""),
    # BLAKE2
    ("BLAKE2s-256",      64, r'^[0-9a-fA-F]+$',   None, ""),
    ("BLAKE2b-512",     128, r'^[0-9a-fA-F]+$',   None, ""),
    # LM
    ("LM",               32, r'^[0-9a-fA-F]+$',   3000, "Windows LAN Manager"),
    # Other
    ("Keccak-256",       64, r'^[0-9a-fA-F]+$',   None, "Ethereum etc."),
    ("HAVAL-128",        32, r'^[0-9a-fA-F]+$',   None, ""),
    ("HAVAL-256",        64, r'^[0-9a-fA-F]+$',   None, ""),
    ("Tiger-192",        48, r'^[0-9a-fA-F]+$',   None, ""),
]


def identify(hash_str: str) -> list[dict]:
    h = hash_str.strip()
    length = len(h)
    matches = []

    for name, expected_len, pattern, hc_mode, notes in SIGNATURES:
        if expected_len is not None and length != expected_len:
            continue
        if re.match(pattern, h, re.IGNORECASE):
            matches.append({
                "name": name,
                "length": length,
                "hashcat_mode": hc_mode,
                "notes": notes,
            })

    return matches


def main():
    parser = argparse.ArgumentParser(description="Identify hash algorithm from hash string")
    parser.add_argument("hash", nargs="?", help="Hash string to identify")
    parser.add_argument("--file", help="File with one hash per line")
    args = parser.parse_args()

    if args.file:
        hashes = open(args.file).read().splitlines()
    elif args.hash:
        hashes = [args.hash]
    else:
        print("[!] Provide a hash or --file")
        sys.exit(1)

    for h in hashes:
        h = h.strip()
        if not h:
            continue
        print(f"\n[*] Hash: {h[:80]}{'...' if len(h) > 80 else ''}")
        print(f"    Length: {len(h)}")
        matches = identify(h)
        if matches:
            print(f"    Possible algorithms:")
            for m in matches:
                hc = f"  hashcat mode: {m['hashcat_mode']}" if m['hashcat_mode'] else ""
                note = f"  [{m['notes']}]" if m['notes'] else ""
                print(f"      {m['name']}{hc}{note}")
        else:
            print("    No matching algorithm found")


if __name__ == "__main__":
    main()
