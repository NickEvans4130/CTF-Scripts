#!/usr/bin/env python3
"""
AES-ECB byte-at-a-time decryption attack.
Recovers a secret appended to attacker-controlled input before ECB encryption.

Provide an oracle via:
  --oracle-script  path to Python file with encrypt(plaintext_hex) -> ciphertext_hex
  --oracle-url     HTTP POST endpoint (sends plaintext_hex, receives ciphertext_hex)
"""

import argparse
import importlib.util
import sys
import urllib.request


# ── Oracle loaders ────────────────────────────────────────────────────────────

def load_script_oracle(path: str):
    spec = importlib.util.spec_from_file_location("oracle", path)
    mod  = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return lambda pt_hex: mod.encrypt(pt_hex)


def make_url_oracle(url: str):
    def oracle(pt_hex: str) -> str:
        data = pt_hex.encode()
        req  = urllib.request.Request(url, data=data, method='POST')
        with urllib.request.urlopen(req) as resp:
            return resp.read().decode().strip()
    return oracle


# ── Detection helpers ─────────────────────────────────────────────────────────

def detect_block_size(oracle) -> int:
    base_len = len(bytes.fromhex(oracle('')))
    for i in range(1, 65):
        ct = bytes.fromhex(oracle('41' * i))
        if len(ct) > base_len:
            return len(ct) - base_len
    raise RuntimeError("Could not detect block size")


def detect_prefix_len(oracle, block_size: int) -> int:
    """Find the length of any static prefix the oracle prepends."""
    ct0 = bytes.fromhex(oracle('41' * block_size * 2))
    ct1 = bytes.fromhex(oracle('42' * block_size * 2))
    # Find first differing block
    for i in range(0, len(ct0), block_size):
        if ct0[i:i + block_size] == ct1[i:i + block_size]:
            continue
        # The differing block index tells us where our input starts
        # Narrow down by varying padding
        for pad in range(block_size):
            ct = bytes.fromhex(oracle('41' * (block_size * 2 - pad)))
            if ct[i:i + block_size] == ct0[i:i + block_size]:
                return i - pad  # rough estimate
        return i
    return 0


# ── Attack ────────────────────────────────────────────────────────────────────

def byte_at_a_time(oracle, block_size: int, prefix_len: int) -> bytes:
    """Recover the secret suffix one byte at a time."""
    # Pad our input so it starts on a block boundary after the prefix
    prefix_pad_len = (-prefix_len) % block_size
    prefix_pad     = 'AA' * prefix_pad_len

    # Find secret length
    base_ct_len = len(bytes.fromhex(oracle(prefix_pad)))
    for i in range(1, block_size + 1):
        new_len = len(bytes.fromhex(oracle(prefix_pad + '41' * i)))
        if new_len > base_ct_len:
            secret_len = base_ct_len - (prefix_len + prefix_pad_len) - i + 1
            break
    else:
        secret_len = base_ct_len - prefix_len - prefix_pad_len

    print(f"[*] Block size:   {block_size}")
    print(f"[*] Prefix len:   {prefix_len}")
    print(f"[*] Secret len:   ~{secret_len}")

    start_block = (prefix_len + prefix_pad_len) // block_size
    recovered   = bytearray()

    for i in range(secret_len):
        # We need (block_size - 1 - i%block_size) bytes of padding before secret
        pad_len = block_size - 1 - (i % block_size)
        our_pad = prefix_pad + '41' * pad_len

        # Target block index
        target_block = start_block + i // block_size

        # Get the oracle output for this padding
        real_ct = bytes.fromhex(oracle(our_pad))
        target  = real_ct[target_block * block_size:(target_block + 1) * block_size]

        # Brute-force the last byte
        found = False
        for guess in range(256):
            # craft = padding + known_recovered + guess
            craft_pt = ('41' * pad_len) + recovered.hex() + f'{guess:02x}'
            craft_ct = bytes.fromhex(oracle(prefix_pad + craft_pt))
            craft_block = craft_ct[start_block * block_size:(start_block + 1) * block_size]
            if craft_block == target:
                recovered.append(guess)
                found = True
                break

        if not found:
            print(f"\n[!] Could not recover byte {i}. Stopping.")
            break

        print(f"\r[*] Recovered {len(recovered)}/{secret_len} bytes: "
              f"{recovered.decode('utf-8', errors='replace')[:60]}", end='', flush=True)

    print()
    return bytes(recovered)


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="AES-ECB byte-at-a-time decryption attack")
    oracle_src = parser.add_mutually_exclusive_group(required=True)
    oracle_src.add_argument("--oracle-script", dest="script")
    oracle_src.add_argument("--oracle-url",    dest="url")
    parser.add_argument("--block-size", type=int, default=0, dest="block_size",
                        help="Force block size (auto-detect if 0)")
    args = parser.parse_args()

    oracle = load_script_oracle(args.script) if args.script else make_url_oracle(args.url)

    block_size = args.block_size or detect_block_size(oracle)
    prefix_len = detect_prefix_len(oracle, block_size)

    secret = byte_at_a_time(oracle, block_size, prefix_len)
    print(f"\n[+] Recovered secret ({len(secret)} bytes):")
    print(secret.decode('utf-8', errors='replace'))


if __name__ == "__main__":
    main()
