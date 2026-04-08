#!/usr/bin/env python3
"""
Monoalphabetic substitution cipher solver using simulated annealing and bigram scoring.
"""

import argparse
import math
import random
import string
from pathlib import Path

EN_UNIGRAM = {
    'E': 12.70, 'T': 9.06, 'A': 8.17, 'O': 7.51, 'I': 6.97, 'N': 6.75,
    'S': 6.33, 'H': 6.09, 'R': 5.99, 'D': 4.25, 'L': 4.03, 'C': 2.78,
    'U': 2.76, 'M': 2.41, 'W': 2.36, 'F': 2.23, 'G': 2.02, 'Y': 1.97,
    'P': 1.93, 'B': 1.49, 'V': 0.98, 'K': 0.77, 'J': 0.15, 'X': 0.15,
    'Q': 0.10, 'Z': 0.07,
}

# Common English bigrams (log probabilities proportional to frequency)
EN_BIGRAMS = {
    'TH': 3.56, 'HE': 3.07, 'IN': 2.43, 'ER': 2.05, 'AN': 1.99,
    'RE': 1.85, 'ON': 1.76, 'AT': 1.49, 'EN': 1.45, 'ND': 1.35,
    'TI': 1.34, 'ES': 1.34, 'OR': 1.28, 'TE': 1.20, 'OF': 1.17,
    'ED': 1.17, 'IS': 1.13, 'IT': 1.12, 'AL': 1.09, 'AR': 1.07,
    'ST': 1.05, 'TO': 1.04, 'NT': 1.04, 'NG': 0.95, 'SE': 0.93,
    'HA': 0.93, 'AS': 0.87, 'OU': 0.87, 'IO': 0.83, 'LE': 0.83,
}
_LOG_BIGRAMS = {k: math.log(v) for k, v in EN_BIGRAMS.items()}
_LOG_DEFAULT = math.log(0.001)


def decrypt(ciphertext: str, key: dict) -> str:
    return ''.join(key.get(c, c) for c in ciphertext.upper())


def fitness(plaintext: str) -> float:
    alpha = ''.join(c for c in plaintext if c.isalpha())
    score = 0.0
    for i in range(len(alpha) - 1):
        bigram = alpha[i:i + 2]
        score += _LOG_BIGRAMS.get(bigram, _LOG_DEFAULT)
    return score


def random_key() -> dict:
    shuffled = list(string.ascii_uppercase)
    random.shuffle(shuffled)
    return dict(zip(string.ascii_uppercase, shuffled))


def swap_two(key: dict) -> dict:
    k = dict(key)
    letters = list(string.ascii_uppercase)
    a, b = random.sample(letters, 2)
    # Find which ciphertext letters map to a and b, then swap
    inv = {v: k2 for k2, v in k.items()}
    ca, cb = inv.get(a, a), inv.get(b, b)
    k[ca], k[cb] = k[cb], k[ca]
    return k


def simulated_annealing(ciphertext: str, iterations: int, restarts: int) -> tuple[dict, str, float]:
    best_key   = random_key()
    best_pt    = decrypt(ciphertext, best_key)
    best_score = fitness(best_pt)

    for _ in range(restarts):
        key   = random_key()
        score = fitness(decrypt(ciphertext, key))
        T     = 10.0

        for i in range(iterations):
            new_key   = swap_two(key)
            new_pt    = decrypt(ciphertext, new_key)
            new_score = fitness(new_pt)
            delta     = new_score - score

            if delta > 0 or random.random() < math.exp(delta / T):
                key, score = new_key, new_score

            if score > best_score:
                best_score = score
                best_key   = dict(key)
                best_pt    = new_pt

            T *= 0.9999  # cooling

    return best_key, best_pt, best_score


def interactive_fix(ciphertext: str, key: dict) -> None:
    print("\n[*] Interactive mode. Commands:")
    print("    swap A B  - swap plaintext mappings for cipher letters A and B")
    print("    set A B   - set cipher letter A to decode as B")
    print("    show      - show current key")
    print("    quit      - exit\n")

    while True:
        pt = decrypt(ciphertext, key)
        print(f"\nCurrent: {pt[:200]}")
        try:
            cmd = input("> ").strip().split()
        except (EOFError, KeyboardInterrupt):
            break
        if not cmd:
            continue
        if cmd[0] == "quit":
            break
        elif cmd[0] == "show":
            print("Key:", {k: v for k, v in sorted(key.items())})
        elif cmd[0] == "swap" and len(cmd) == 3:
            a, b = cmd[1].upper(), cmd[2].upper()
            inv = {v: k2 for k2, v in key.items()}
            ca, cb = inv.get(a, a), inv.get(b, b)
            key[ca], key[cb] = key[cb], key[ca]
        elif cmd[0] == "set" and len(cmd) == 3:
            a, b = cmd[1].upper(), cmd[2].upper()
            key[a] = b
        else:
            print("Unknown command")

    print("\n[+] Final plaintext:")
    print(decrypt(ciphertext, key))


def main():
    parser = argparse.ArgumentParser(description="Substitution cipher solver (simulated annealing)")
    src = parser.add_mutually_exclusive_group(required=True)
    src.add_argument("ciphertext", nargs="?")
    src.add_argument("--file", help="Read ciphertext from file")
    parser.add_argument("--iterations", type=int, default=10_000,
                        help="SA iterations per restart (default: 10000)")
    parser.add_argument("--restarts", type=int, default=5,
                        help="Number of random restarts (default: 5)")
    parser.add_argument("--interactive", action="store_true",
                        help="Enter interactive mode to fix mappings after SA")
    args = parser.parse_args()

    text = Path(args.file).read_text() if args.file else args.ciphertext
    ct   = ''.join(c for c in text.upper() if c.isalpha() or not c.isalnum())

    print(f"[*] Ciphertext ({len(ct)} chars): {ct[:80]}")
    print(f"[*] Running simulated annealing ({args.restarts} restarts x {args.iterations} iterations) ...")

    key, pt, sc = simulated_annealing(ct, args.iterations, args.restarts)

    print(f"\n[+] Best score: {sc:.2f}")
    print(f"[+] Key: {''.join(key[c] for c in string.ascii_uppercase)}")
    print(f"[+] Plaintext:\n{pt[:500]}")

    if args.interactive:
        interactive_fix(ct, key)


if __name__ == "__main__":
    main()
