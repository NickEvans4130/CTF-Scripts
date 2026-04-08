#!/usr/bin/env python3
"""
Vigenère cipher cracker using Index of Coincidence (IC) key-length estimation
and per-column frequency analysis for key recovery.
"""

import argparse
import string
from pathlib import Path

EN_IC   = 0.0667   # expected IC for English
RAND_IC = 0.0385   # expected IC for random text

EN_FREQ = [8.17,1.49,2.78,4.25,12.70,2.23,2.02,6.09,6.97,0.15,0.77,4.03,
           2.41,6.75,7.51,1.93,0.10,5.99,6.33,9.06,2.76,0.98,2.36,0.15,1.97,0.07]


def letters_only(text: str) -> str:
    return ''.join(c.upper() for c in text if c.isalpha())


def index_of_coincidence(text: str) -> float:
    n = len(text)
    if n < 2:
        return 0.0
    freq = [text.count(chr(65 + i)) for i in range(26)]
    return sum(f * (f - 1) for f in freq) / (n * (n - 1))


def estimate_key_length(ciphertext: str, max_len: int = 30) -> list[tuple[float, int]]:
    """Return key lengths sorted by how close their IC is to English."""
    results = []
    for kl in range(1, max_len + 1):
        columns = [''.join(ciphertext[i::kl]) for i in range(kl)]
        avg_ic = sum(index_of_coincidence(col) for col in columns) / kl
        delta = abs(avg_ic - EN_IC)
        results.append((delta, kl))
    results.sort()
    return results


def crack_column(column: str) -> tuple[int, str]:
    """Return (key_byte, decrypted_column) for a single Vigenère column."""
    best_score = -1
    best_shift = 0
    n = len(column)
    for shift in range(26):
        decrypted = ''.join(chr((ord(c) - 65 - shift) % 26 + 65) for c in column)
        freq = [decrypted.count(chr(65 + i)) / n for i in range(26)]
        score = sum(freq[i] * EN_FREQ[i] for i in range(26))
        if score > best_score:
            best_score = score
            best_shift = shift
    decrypted = ''.join(chr((ord(c) - 65 - best_shift) % 26 + 65) for c in column)
    return best_shift, decrypted


def decrypt_vigenere(ciphertext: str, key: str) -> str:
    result = []
    ki = 0
    for c in ciphertext:
        if c.isalpha():
            shift = ord(key[ki % len(key)].upper()) - 65
            if c.isupper():
                result.append(chr((ord(c) - 65 - shift) % 26 + 65))
            else:
                result.append(chr((ord(c) - 97 - shift) % 26 + 97))
            ki += 1
        else:
            result.append(c)
    return ''.join(result)


def main():
    parser = argparse.ArgumentParser(description="Crack Vigenère cipher via IC analysis")
    src = parser.add_mutually_exclusive_group(required=True)
    src.add_argument("ciphertext", nargs="?")
    src.add_argument("--file", help="Read ciphertext from file")
    parser.add_argument("--max-keylen", type=int, default=30, help="Max key length to test (default: 30)")
    parser.add_argument("--top", type=int, default=3, help="Try top N key length candidates (default: 3)")
    parser.add_argument("--key", help="Decrypt with a known key instead")
    args = parser.parse_args()

    raw = Path(args.file).read_text() if args.file else args.ciphertext
    ct_letters = letters_only(raw)
    print(f"[*] Ciphertext length: {len(ct_letters)} alphabetic characters")

    if args.key:
        pt = decrypt_vigenere(raw, args.key)
        print(f"[+] Key: {args.key.upper()}")
        print(f"[+] Plaintext:\n{pt}")
        return

    ranked = estimate_key_length(ct_letters, args.max_keylen)
    print(f"\n[*] Top key length candidates:")
    for delta, kl in ranked[:args.top]:
        print(f"    length={kl}  IC_delta={delta:.5f}")

    for _, key_len in ranked[:args.top]:
        columns = [ct_letters[i::key_len] for i in range(key_len)]
        key_bytes = []
        for col in columns:
            shift, _ = crack_column(col)
            key_bytes.append(chr(shift + 65))
        key = ''.join(key_bytes)
        plaintext = decrypt_vigenere(raw, key)
        print(f"\n[+] Key length {key_len} -> Key: {key}")
        print(f"    Plaintext: {plaintext[:120]}")


if __name__ == "__main__":
    main()
