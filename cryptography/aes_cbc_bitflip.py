#!/usr/bin/env python3
"""
AES-CBC bit-flipping attack.
Flips bits in ciphertext block N-1 to control the decryption of block N.
"""

import argparse
import sys


def bitflip(ciphertext: bytes, block_size: int,
            target_offset: int, current_byte: int, desired_byte: int) -> bytes:
    """
    Flip the byte at `target_offset` in the plaintext by modifying
    the corresponding byte in the previous ciphertext block.

    AES-CBC decrypt: P[i] = D(C[i]) XOR C[i-1]
    So: P[i][j] = D(C[i])[j] XOR C[i-1][j]
    To change P[i][j] from current to desired:
        C[i-1][j] ^= current ^ desired

    target_offset is the absolute byte offset into the plaintext.
    """
    if target_offset < block_size:
        print("[!] Cannot flip block 0 (no previous ciphertext block). "
              "target_offset must be >= block_size.")
        sys.exit(1)

    ct = bytearray(ciphertext)
    # The byte we flip is in the block before the target block
    prev_block_byte = target_offset - block_size
    ct[prev_block_byte] ^= current_byte ^ desired_byte
    return bytes(ct)


def flip_string(ciphertext: bytes, block_size: int,
                target_offset: int, current_str: str, desired_str: str) -> bytes:
    """Flip multiple bytes to change a substring in the plaintext."""
    if len(current_str) != len(desired_str):
        print("[!] current and desired strings must be the same length")
        sys.exit(1)
    ct = ciphertext
    for i, (c, d) in enumerate(zip(current_str.encode(), desired_str.encode())):
        ct = bitflip(ct, block_size, target_offset + i, c, d)
    return ct


def main():
    parser = argparse.ArgumentParser(description="AES-CBC bit-flipping attack")
    parser.add_argument("--ciphertext", required=True, help="Hex-encoded ciphertext (includes IV as first block)")
    parser.add_argument("--block-size", type=int, default=16, dest="block_size",
                        help="Block size in bytes (default: 16)")
    parser.add_argument("--target-offset", type=int, required=True, dest="target_offset",
                        help="Byte offset in plaintext to modify")
    parser.add_argument("--current", required=True,
                        help="Current plaintext value at offset (string or 0xHH for single byte)")
    parser.add_argument("--desired", required=True,
                        help="Desired plaintext value at offset (string or 0xHH for single byte)")
    args = parser.parse_args()

    ct = bytes.fromhex(args.ciphertext)
    bs = args.block_size

    if args.current.startswith('0x') and args.desired.startswith('0x'):
        curr_b = int(args.current, 16)
        des_b  = int(args.desired, 16)
        forged = bitflip(ct, bs, args.target_offset, curr_b, des_b)
    else:
        forged = flip_string(ct, bs, args.target_offset, args.current, args.desired)

    print(f"[*] Original ciphertext: {ct.hex()}")
    print(f"[+] Forged  ciphertext: {forged.hex()}")
    print(f"\n[*] Target offset:  {args.target_offset} (block {args.target_offset // bs}, byte {args.target_offset % bs})")
    print(f"[*] Modified byte:  ciphertext offset {args.target_offset - bs}")

    # Show diff
    diffs = [i for i in range(len(ct)) if ct[i] != forged[i]]
    print(f"[*] Changed bytes: {diffs}")

    # Warn about garbled block
    garbled_block = (args.target_offset - bs) // bs
    print(f"[!] Block {garbled_block} of plaintext will be garbled (XOR corruption side effect)")


if __name__ == "__main__":
    main()
