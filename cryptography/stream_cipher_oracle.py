#!/usr/bin/env python3
"""
Generic stream cipher oracle tool.
Modes:
  recover   - recover keystream bytes from a known plaintext XOR
  crib-drag - slide a crib across multiple ciphertexts (nonce-reuse)
  detect    - detect nonce/key reuse by comparing ciphertext pairs
"""

import argparse
import sys
from pathlib import Path

EN_FREQ = {
    ord(' '): 13.0, ord('e'): 12.7, ord('t'): 9.1, ord('a'): 8.2,
    ord('o'): 7.5,  ord('i'): 7.0,  ord('n'): 6.7, ord('s'): 6.3,
    ord('h'): 6.1,  ord('r'): 6.0,  ord('d'): 4.2,
}
for k in list(EN_FREQ):
    if 97 <= k <= 122:
        EN_FREQ[k - 32] = EN_FREQ[k] * 0.5


def score(data: bytes) -> float:
    return sum(EN_FREQ.get(b, 0) for b in data)


def xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def load_hex_file(path: Path) -> list[bytes]:
    return [bytes.fromhex(l.strip()) for l in path.read_text().splitlines() if l.strip()]


# ── Mode: recover ─────────────────────────────────────────────────────────────

def mode_recover(ct: bytes, known: bytes, offset: int) -> None:
    if offset + len(known) > len(ct):
        print("[!] Known plaintext extends beyond ciphertext length")
        sys.exit(1)
    ks_frag = xor(ct[offset:offset + len(known)], known)
    print(f"[+] Keystream bytes [{offset}:{offset + len(known)}]: {ks_frag.hex()}")
    print(f"    (as bytes): {ks_frag!r}")

    # Apply keystream fragment to decrypt surrounding context
    ctx_start = max(0, offset - 20)
    ctx_len   = min(len(ct) - ctx_start, len(ks_frag) + 40)
    ks_padded = b'\x00' * (offset - ctx_start) + ks_frag
    decrypted = xor(ct[ctx_start:ctx_start + len(ks_padded)], ks_padded)
    printable = decrypted.decode('utf-8', errors='replace')
    print(f"\n[+] Decrypted context (offset {ctx_start}):")
    print(f"    {printable!r}")


# ── Mode: crib-drag ───────────────────────────────────────────────────────────

def mode_crib_drag(ciphertexts: list[bytes], crib: bytes, top: int) -> None:
    results = []
    for ci, ct in enumerate(ciphertexts):
        for offset in range(len(ct) - len(crib) + 1):
            ks = xor(ct[offset:offset + len(crib)], crib)
            total_score = 0.0
            for other in ciphertexts:
                chunk = xor(other[offset:offset + len(crib)], ks)
                total_score += score(chunk)
            results.append((total_score, ci, offset, ks))

    results.sort(reverse=True)
    print(f"[*] Top {top} crib results for {crib!r}:")
    print(f"{'Score':>10}  {'CT#':>4}  {'Offset':>7}  Keystream   Decrypted (CT#0)")
    print("-" * 72)
    for sc, ci, off, ks in results[:top]:
        ctx = xor(ciphertexts[0][off:off + len(crib)], ks)
        ctx_s = ctx.decode('utf-8', errors='replace')
        print(f"{sc:>10.2f}  {ci:>4}  {off:>7}  {ks.hex():<12}  {ctx_s!r}")


# ── Mode: detect reuse ────────────────────────────────────────────────────────

def mode_detect_reuse(ciphertexts: list[bytes]) -> None:
    print("[*] Checking all ciphertext pairs for likely nonce reuse ...")
    print("    (high English score on XOR suggests shared keystream)\n")
    pairs = []
    for i in range(len(ciphertexts)):
        for j in range(i + 1, len(ciphertexts)):
            xored = xor(ciphertexts[i], ciphertexts[j])
            sc    = score(xored)
            pairs.append((sc, i, j, xored))

    pairs.sort(reverse=True)
    print(f"{'Score':>10}  Pair     XOR preview (first 20 bytes)")
    print("-" * 60)
    for sc, i, j, xored in pairs[:20]:
        preview = xored[:20].decode('utf-8', errors='replace')
        print(f"{sc:>10.2f}  CT{i} x CT{j}  {preview!r}")


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Generic stream cipher oracle tool")
    parser.add_argument("--mode", required=True, choices=["recover", "crib-drag", "detect-reuse"])

    # recover mode
    parser.add_argument("--ciphertext", help="Hex-encoded ciphertext (for recover mode)")
    parser.add_argument("--known",      help="Known plaintext string")
    parser.add_argument("--offset",     type=int, default=0,
                        help="Byte offset of known plaintext in ciphertext (default: 0)")

    # multi-ciphertext modes
    parser.add_argument("--ciphertexts", help="File with one hex ciphertext per line")
    parser.add_argument("--crib",        help="Crib string for crib-drag mode")
    parser.add_argument("--top",         type=int, default=10)
    args = parser.parse_args()

    if args.mode == "recover":
        if not args.ciphertext or not args.known:
            print("[!] --mode recover requires --ciphertext and --known")
            sys.exit(1)
        mode_recover(bytes.fromhex(args.ciphertext), args.known.encode(), args.offset)

    elif args.mode == "crib-drag":
        if not args.ciphertexts or not args.crib:
            print("[!] --mode crib-drag requires --ciphertexts and --crib")
            sys.exit(1)
        cts = load_hex_file(Path(args.ciphertexts))
        mode_crib_drag(cts, args.crib.encode(), args.top)

    elif args.mode == "detect-reuse":
        if not args.ciphertexts:
            print("[!] --mode detect-reuse requires --ciphertexts")
            sys.exit(1)
        cts = load_hex_file(Path(args.ciphertexts))
        mode_detect_reuse(cts)


if __name__ == "__main__":
    main()
