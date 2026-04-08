#!/usr/bin/env python3
"""
XOR single-byte and multi-byte key brute-forcer with frequency scoring.
Multi-byte mode uses normalised Hamming distance to estimate key length.
"""

import argparse
import itertools
from pathlib import Path

EN_FREQ = {
    b'e': 12.70, b't': 9.06, b'a': 8.17, b'o': 7.51, b'i': 6.97, b'n': 6.75,
    b's': 6.33, b'h': 6.09, b'r': 5.99, b'd': 4.25, b'l': 4.03, b'c': 2.78,
    b'u': 2.76, b'm': 2.41, b'w': 2.36, b'f': 2.23, b'g': 2.02, b'y': 1.97,
    b'p': 1.93, b'b': 1.49, b'v': 0.98, b'k': 0.77, b' ': 13.00,
}


def score_bytes(data: bytes) -> float:
    return sum(EN_FREQ.get(bytes([b]).lower(), 0) for b in data)


def xor_single(data: bytes, key: int) -> bytes:
    return bytes(b ^ key for b in data)


def xor_multi(data: bytes, key: bytes) -> bytes:
    kl = len(key)
    return bytes(data[i] ^ key[i % kl] for i in range(len(data)))


def hamming_distance(a: bytes, b: bytes) -> int:
    return sum(bin(x ^ y).count('1') for x, y in zip(a, b))


def estimate_key_lengths(data: bytes, max_len: int = 40, n_blocks: int = 4) -> list[tuple[float, int]]:
    scores = []
    for kl in range(1, min(max_len + 1, len(data) // 2)):
        blocks = [data[i * kl:(i + 1) * kl] for i in range(min(n_blocks, len(data) // kl))]
        if len(blocks) < 2:
            continue
        pairs = list(itertools.combinations(blocks, 2))
        normalised = sum(hamming_distance(a, b) / kl for a, b in pairs) / len(pairs)
        scores.append((normalised, kl))
    scores.sort()
    return scores


def crack_single_byte(data: bytes) -> tuple[int, bytes, float]:
    best = max(
        ((k, xor_single(data, k), score_bytes(xor_single(data, k))) for k in range(256)),
        key=lambda x: x[2]
    )
    return best


def crack_multi_byte(data: bytes, key_len: int) -> bytes:
    columns = [data[i::key_len] for i in range(key_len)]
    key = bytes(crack_single_byte(col)[0] for col in columns)
    return key


def main():
    parser = argparse.ArgumentParser(description="XOR single-byte and multi-byte key brute-forcer")
    src = parser.add_mutually_exclusive_group(required=True)
    src.add_argument("--hex", help="Hex-encoded ciphertext")
    src.add_argument("--file", help="Raw binary ciphertext file")
    parser.add_argument("--single", action="store_true", help="Single-byte XOR mode")
    parser.add_argument("--keylen", type=int, help="Force this multi-byte key length")
    parser.add_argument("--max-keylen", type=int, default=40, help="Max key length to try (default: 40)")
    parser.add_argument("--top", type=int, default=3, help="Show top N key length candidates (default: 3)")
    args = parser.parse_args()

    if args.hex:
        data = bytes.fromhex(args.hex.replace(' ', ''))
    else:
        data = Path(args.file).read_bytes()

    print(f"[*] Ciphertext: {len(data)} bytes")

    if args.single:
        key, plaintext, sc = crack_single_byte(data)
        print(f"[+] Key: 0x{key:02x} ({chr(key) if 32 <= key < 127 else '?'})")
        print(f"[+] Score: {sc:.2f}")
        print(f"[+] Plaintext: {plaintext[:200]}")
        return

    if args.keylen:
        candidates = [(0.0, args.keylen)]
    else:
        candidates = estimate_key_lengths(data, args.max_keylen)
        print(f"\n[*] Top key length candidates:")
        for dist, kl in candidates[:args.top]:
            print(f"    length={kl}  norm_hamming={dist:.4f}")

    for _, kl in candidates[:args.top]:
        key = crack_multi_byte(data, kl)
        plaintext = xor_multi(data, key)
        sc = score_bytes(plaintext)
        print(f"\n[+] Key length {kl}: {key.hex()}  ({key!r})")
        print(f"    Score: {sc:.2f}")
        try:
            print(f"    Plaintext: {plaintext[:200].decode('utf-8', errors='replace')}")
        except Exception:
            print(f"    Plaintext (hex): {plaintext[:64].hex()}")


if __name__ == "__main__":
    main()
