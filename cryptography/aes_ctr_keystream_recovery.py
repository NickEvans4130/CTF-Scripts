#!/usr/bin/env python3
"""
AES-CTR keystream recovery from reused nonces.
Recovers keystream bytes using frequency analysis / crib-dragging across multiple ciphertexts.
"""

import argparse
import sys
from pathlib import Path

EN_FREQ_BYTES = {
    ord('e'): 12.70, ord('t'): 9.06, ord('a'): 8.17, ord('o'): 7.51,
    ord('i'): 6.97,  ord('n'): 6.75, ord('s'): 6.33, ord('h'): 6.09,
    ord('r'): 5.99,  ord('d'): 4.25, ord('l'): 4.03, ord('c'): 2.78,
    ord('u'): 2.76,  ord('m'): 2.41, ord('w'): 2.36, ord('f'): 2.23,
    ord('g'): 2.02,  ord('y'): 1.97, ord('p'): 1.93, ord('b'): 1.49,
    ord(' '): 13.00,
}

for k in list(EN_FREQ_BYTES):
    EN_FREQ_BYTES[k ^ 0x20] = EN_FREQ_BYTES[k] * 0.5  # uppercase gets half weight


def score(data: bytes) -> float:
    return sum(EN_FREQ_BYTES.get(b, 0) for b in data)


def load_ciphertexts(path: Path) -> list[bytes]:
    lines = path.read_text().strip().splitlines()
    return [bytes.fromhex(line.strip()) for line in lines if line.strip()]


def recover_keystream_byte(ciphertexts: list[bytes], position: int) -> int:
    """For a given position, collect all ciphertext bytes and find the best keystream byte."""
    column = [ct[position] for ct in ciphertexts if position < len(ct)]
    if not column:
        return 0
    best_score = -1
    best_k = 0
    for k in range(256):
        decrypted = bytes(b ^ k for b in column)
        s = score(decrypted)
        if s > best_score:
            best_score = s
            best_k = k
    return best_k


def crib_drag(ciphertexts: list[bytes], crib: bytes, top: int) -> None:
    max_len = max(len(ct) for ct in ciphertexts)
    results = []

    for ct_idx, ct in enumerate(ciphertexts):
        for offset in range(len(ct) - len(crib) + 1):
            # XOR crib with ciphertext at offset to get keystream fragment
            ks_frag = bytes(ct[offset + i] ^ crib[i] for i in range(len(crib)))
            # Apply keystream fragment to all other ciphertexts
            total_score = 0.0
            for other_ct in ciphertexts:
                decrypted = bytes(
                    other_ct[offset + i] ^ ks_frag[i]
                    for i in range(len(crib))
                    if offset + i < len(other_ct)
                )
                total_score += score(decrypted)
            results.append((total_score, ct_idx, offset, ks_frag))

    results.sort(reverse=True)
    print(f"\n[*] Top {top} crib positions for {crib!r}:")
    print(f"{'Score':>10}  {'CT':>4}  {'Offset':>7}  Keystream fragment")
    print("-" * 60)
    for sc, ct_idx, offset, ks in results[:top]:
        print(f"{sc:>10.2f}  {ct_idx:>4}  {offset:>7}  {ks.hex()}")


def auto_recover_keystream(ciphertexts: list[bytes]) -> bytes:
    max_len = max(len(ct) for ct in ciphertexts)
    keystream = bytearray(max_len)
    for pos in range(max_len):
        keystream[pos] = recover_keystream_byte(ciphertexts, pos)
        print(f"\r[*] Recovering keystream ... position {pos+1}/{max_len}", end='', flush=True)
    print()
    return bytes(keystream)


def main():
    parser = argparse.ArgumentParser(description="AES-CTR keystream recovery from reused nonces")
    parser.add_argument("--ciphertexts", required=True,
                        help="File with one hex ciphertext per line (all encrypted with the same nonce)")
    parser.add_argument("--crib", help="Known plaintext fragment to crib-drag across ciphertexts")
    parser.add_argument("--top", type=int, default=10,
                        help="Number of top crib-drag results to show (default: 10)")
    parser.add_argument("--auto", action="store_true",
                        help="Auto-recover full keystream using frequency analysis")
    args = parser.parse_args()

    ciphertexts = load_ciphertexts(Path(args.ciphertexts))
    print(f"[*] Loaded {len(ciphertexts)} ciphertexts")
    for i, ct in enumerate(ciphertexts):
        print(f"    [{i}] {ct[:20].hex()}...  ({len(ct)} bytes)")

    if args.crib:
        crib_drag(ciphertexts, args.crib.encode(), args.top)

    if args.auto or not args.crib:
        keystream = auto_recover_keystream(ciphertexts)
        print(f"\n[+] Recovered keystream ({len(keystream)} bytes): {keystream.hex()}")
        print("\n[+] Decrypting all ciphertexts:")
        for i, ct in enumerate(ciphertexts):
            pt = bytes(ct[j] ^ keystream[j] for j in range(len(ct)))
            print(f"  [{i}] {pt.decode('utf-8', errors='replace')}")


if __name__ == "__main__":
    main()
