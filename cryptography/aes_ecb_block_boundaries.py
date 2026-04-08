#!/usr/bin/env python3
"""
AES-ECB mode detection and block boundary finder.
Detects ECB by looking for repeated 16-byte blocks, determines block size,
and measures prefix length so byte-at-a-time attacks can be aligned correctly.
"""

import argparse
import importlib.util
import sys
import urllib.request


def load_oracle(script: str | None, url: str | None):
    if script:
        spec = importlib.util.spec_from_file_location("oracle", script)
        mod  = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return lambda pt_hex: mod.encrypt(pt_hex)
    def url_oracle(pt_hex: str) -> str:
        req = urllib.request.Request(url, data=pt_hex.encode(), method='POST')
        with urllib.request.urlopen(req) as r:
            return r.read().decode().strip()
    return url_oracle


def detect_block_size(oracle) -> int:
    base = len(bytes.fromhex(oracle('')))
    for i in range(1, 65):
        ct = bytes.fromhex(oracle('41' * i))
        if len(ct) > base:
            return len(ct) - base
    raise RuntimeError("Could not detect block size (oracle output did not grow)")


def is_ecb(oracle, block_size: int) -> bool:
    """Send 3 identical blocks and check for repeated ciphertext blocks."""
    ct = bytes.fromhex(oracle('41' * block_size * 3))
    blocks = [ct[i:i + block_size] for i in range(0, len(ct), block_size)]
    return len(blocks) != len(set(blocks))


def detect_prefix_len(oracle, block_size: int) -> int:
    """
    Find the number of bytes the oracle prepends before our input.
    Strategy: send incrementally longer payloads of identical bytes until
    two consecutive blocks in the output are equal (our aligned blocks).
    """
    for pad_len in range(block_size * 2 + 1):
        ct = bytes.fromhex(oracle('41' * (block_size * 2 + pad_len)))
        blocks = [ct[i:i + block_size] for i in range(0, len(ct), block_size)]
        for i in range(len(blocks) - 1):
            if blocks[i] == blocks[i + 1]:
                # Our two identical blocks start at block i
                # The prefix fills block 0..i-1 plus `pad_len` bytes into block i
                prefix_len = i * block_size - pad_len
                return max(0, prefix_len)
    return 0


def visualise_blocks(oracle, block_size: int, prefix_len: int) -> None:
    """Print a coloured block map of the ciphertext with varying input lengths."""
    print(f"\n[*] Block map (each column = one {block_size}-byte ciphertext block)")
    print(f"    Blocks that change between inputs are marked with *\n")

    results = {}
    for pad in range(block_size + 1):
        ct = bytes.fromhex(oracle('41' * pad))
        blocks = [ct[i:i + block_size].hex()[:8] for i in range(0, min(len(ct), block_size * 10), block_size)]
        results[pad] = blocks

    max_blocks = max(len(v) for v in results.values())
    base = results[0]

    header = ' '.join(f'B{i:<7}' for i in range(max_blocks))
    print(f"{'pad':>4}  {header}")

    for pad, blocks in results.items():
        row = []
        for i, b in enumerate(blocks):
            ref = base[i] if i < len(base) else '????????'
            row.append(f'{"*" if b != ref else " "}{b}')
        print(f"{pad:>4}  {" ".join(row)}")


def main():
    parser = argparse.ArgumentParser(description="AES-ECB detection and block boundary finder")
    oracle_src = parser.add_mutually_exclusive_group(required=True)
    oracle_src.add_argument("--oracle-script", dest="script",
                            help="Python file with encrypt(plaintext_hex) -> ciphertext_hex")
    oracle_src.add_argument("--oracle-url", dest="url",
                            help="HTTP POST endpoint for oracle")
    parser.add_argument("--block-size", type=int, default=0, dest="block_size",
                        help="Force block size (auto-detect if 0)")
    parser.add_argument("--visualise", action="store_true",
                        help="Print block map across padding lengths")
    args = parser.parse_args()

    oracle = load_oracle(args.script, args.url)

    block_size = args.block_size or detect_block_size(oracle)
    print(f"[+] Block size:   {block_size} bytes")

    ecb = is_ecb(oracle, block_size)
    print(f"[+] ECB mode:     {'YES - repeated blocks detected' if ecb else 'NO (may be CBC or other)'}")

    if ecb:
        prefix_len = detect_prefix_len(oracle, block_size)
        prefix_pad_needed = (-prefix_len) % block_size
        print(f"[+] Prefix length:         {prefix_len} bytes")
        print(f"[+] Padding needed to align: {prefix_pad_needed} bytes")
        print(f"[+] First controllable block: {(prefix_len + prefix_pad_needed) // block_size}")

    if args.visualise:
        visualise_blocks(oracle, block_size, prefix_len if ecb else 0)


if __name__ == "__main__":
    main()
