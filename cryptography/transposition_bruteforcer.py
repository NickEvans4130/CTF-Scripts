#!/usr/bin/env python3
"""
Rail fence and columnar transposition cipher brute-forcers with frequency scoring.
"""

import argparse
import itertools
import math
import string

EN_FREQ = {
    'E': 12.70, 'T': 9.06, 'A': 8.17, 'O': 7.51, 'I': 6.97, 'N': 6.75,
    'S': 6.33, 'H': 6.09, 'R': 5.99, 'D': 4.25, 'L': 4.03, 'C': 2.78,
    'U': 2.76, 'M': 2.41, 'W': 2.36, 'F': 2.23, 'G': 2.02, 'Y': 1.97,
    'P': 1.93, 'B': 1.49, 'V': 0.98, 'K': 0.77, 'J': 0.15, 'X': 0.15,
    'Q': 0.10, 'Z': 0.07,
}


def score(text: str) -> float:
    alpha = [c.upper() for c in text if c.isalpha()]
    if not alpha:
        return 0.0
    return sum(EN_FREQ.get(c, 0) for c in alpha) / len(alpha)


# ── Rail fence ────────────────────────────────────────────────────────────────

def rail_fence_decrypt(ciphertext: str, rails: int) -> str:
    n = len(ciphertext)
    pattern = []
    rail = 0
    direction = 1
    for i in range(n):
        pattern.append(rail)
        if rail == 0:
            direction = 1
        elif rail == rails - 1:
            direction = -1
        rail += direction

    # Build rail lengths
    counts = [pattern.count(r) for r in range(rails)]
    # Slice ciphertext into rails
    rails_data: list[list[str]] = []
    pos = 0
    for count in counts:
        rails_data.append(list(ciphertext[pos:pos + count]))
        pos += count

    # Read off in zigzag order
    rail_indices = [0] * rails
    result = []
    for r in pattern:
        result.append(rails_data[r][rail_indices[r]])
        rail_indices[r] += 1
    return ''.join(result)


# ── Columnar transposition ────────────────────────────────────────────────────

def columnar_decrypt(ciphertext: str, key_order: tuple) -> str:
    """Decrypt columnar transposition given a column ordering (0-indexed permutation)."""
    n_cols = len(key_order)
    n_rows = math.ceil(len(ciphertext) / n_cols)
    n_full = len(ciphertext) % n_cols  # columns with one extra row
    if n_full == 0:
        n_full = n_cols

    # Build column lengths in key order
    col_lens = []
    for col in range(n_cols):
        # Columns whose key_order position < n_full get an extra char
        original_pos = key_order.index(col)
        col_lens.append(n_rows if original_pos < n_full else n_rows - 1)

    # Slice ciphertext into columns (sorted by key)
    cols = []
    pos = 0
    sorted_cols = sorted(range(n_cols), key=lambda c: key_order[c])
    temp_cols: dict[int, list] = {}
    for col_idx in sorted_cols:
        length = col_lens[col_idx]
        temp_cols[col_idx] = list(ciphertext[pos:pos + length])
        pos += length

    # Read row by row
    result = []
    for row in range(n_rows):
        for col in range(n_cols):
            if row < len(temp_cols[col]):
                result.append(temp_cols[col][row])
    return ''.join(result)


def main():
    parser = argparse.ArgumentParser(description="Rail fence and columnar transposition brute-forcer")
    parser.add_argument("--mode", choices=["rail", "columnar"], required=True)
    parser.add_argument("ciphertext", help="Ciphertext to decrypt")
    parser.add_argument("--max-rails", type=int, default=20,
                        help="Max rails to try for rail fence (default: 20)")
    parser.add_argument("--max-cols",  type=int, default=8,
                        help="Max columns to try for columnar (default: 8)")
    parser.add_argument("--top",       type=int, default=5,
                        help="Show top N results (default: 5)")
    args = parser.parse_args()

    ct = args.ciphertext
    results = []

    if args.mode == "rail":
        print(f"[*] Trying {args.max_rails - 1} rail counts ...")
        for rails in range(2, args.max_rails + 1):
            pt = rail_fence_decrypt(ct, rails)
            results.append((score(pt), f"rails={rails}", pt))

    elif args.mode == "columnar":
        print(f"[*] Trying columnar with 2..{args.max_cols} columns ...")
        for n_cols in range(2, args.max_cols + 1):
            # Try all permutations up to a limit (factorial grows fast)
            perms = list(itertools.permutations(range(n_cols)))
            if len(perms) > 5040:  # cap at 7!
                print(f"    Skipping {n_cols} cols ({len(perms)} permutations)")
                continue
            for perm in perms:
                try:
                    pt = columnar_decrypt(ct, list(perm))
                    results.append((score(pt), f"cols={n_cols} key={perm}", pt))
                except Exception:
                    pass

    results.sort(reverse=True)
    print(f"\n{'Score':>8}  {'Parameters':<30}  Plaintext")
    print("-" * 80)
    for sc, params, pt in results[:args.top]:
        print(f"{sc:>8.3f}  {params:<30}  {pt[:60]}")


if __name__ == "__main__":
    main()
