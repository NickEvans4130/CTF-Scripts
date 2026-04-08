#!/usr/bin/env python3
"""
XOR key recovery from known plaintext, with crib-dragging for unknown offset.
"""

import argparse
from pathlib import Path

EN_FREQ = {
    b'e': 12.70, b't': 9.06, b'a': 8.17, b'o': 7.51, b'i': 6.97, b'n': 6.75,
    b's': 6.33, b'h': 6.09, b'r': 5.99, b'd': 4.25, b'l': 4.03, b'c': 2.78,
    b'u': 2.76, b'm': 2.41, b'w': 2.36, b'f': 2.23, b'g': 2.02, b'y': 1.97,
    b'p': 1.93, b'b': 1.49, b'v': 0.98, b'k': 0.77, b' ': 13.00,
}


def score_bytes(data: bytes) -> float:
    return sum(EN_FREQ.get(bytes([b]).lower(), 0.0) for b in data)


def xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def recover_key_at_offset(cipher: bytes, known: bytes, offset: int) -> bytes:
    """XOR cipher[offset:offset+len(known)] with known to get key bytes."""
    segment = cipher[offset:offset + len(known)]
    return xor(segment, known)


def extend_key(cipher: bytes, key_fragment: bytes, key_offset: int) -> bytes | None:
    """
    Try to extend a key fragment by assuming the key repeats.
    Tests multiples of the fragment length.
    """
    frag_len = len(key_fragment)
    # Guess key period = frag_len
    key = bytearray(frag_len)
    for i, kb in enumerate(key_fragment):
        key[(key_offset + i) % frag_len] = kb
    return bytes(key)


def crib_drag(cipher: bytes, crib: bytes, top: int) -> None:
    """Slide the crib across the ciphertext, scoring each position."""
    results = []
    for offset in range(len(cipher) - len(crib) + 1):
        key_frag = recover_key_at_offset(cipher, crib, offset)
        # Score the surrounding decrypted context
        context_start = max(0, offset - 10)
        context_end   = min(len(cipher), offset + len(crib) + 10)
        key_guess = (key_frag * ((len(cipher) // len(key_frag)) + 2))[:len(cipher)]
        decrypted = xor(cipher[context_start:context_end],
                        key_guess[context_start:context_end])
        sc = score_bytes(decrypted)
        results.append((sc, offset, key_frag, decrypted))

    results.sort(reverse=True)
    print(f"{'Offset':<8} {'Score':>8}  Key fragment (hex)  Decrypted context")
    print("-" * 80)
    for sc, offset, kf, ctx in results[:top]:
        ctx_str = ctx.decode('utf-8', errors='replace').replace('\n', ' ')
        print(f"{offset:<8} {sc:>8.2f}  {kf.hex():<20}  {ctx_str}")


def main():
    parser = argparse.ArgumentParser(description="XOR known-plaintext key recovery and crib-dragging")
    src = parser.add_mutually_exclusive_group(required=True)
    src.add_argument("--hex",  help="Hex-encoded ciphertext")
    src.add_argument("--file", help="Raw binary ciphertext file")
    parser.add_argument("--known",   required=True, help="Known plaintext string (e.g. 'CTF{' or 'flag{')")
    parser.add_argument("--offset",  type=int, default=None,
                        help="Known offset of the plaintext in the ciphertext")
    parser.add_argument("--crib-drag", action="store_true",
                        help="Slide the known plaintext across all positions")
    parser.add_argument("--top",    type=int, default=10,
                        help="Show top N crib-drag results (default: 10)")
    args = parser.parse_args()

    if args.hex:
        cipher = bytes.fromhex(args.hex.replace(' ', ''))
    else:
        cipher = Path(args.file).read_bytes()

    known = args.known.encode()
    print(f"[*] Ciphertext: {len(cipher)} bytes  Crib: {known!r} ({len(known)} bytes)")

    if args.crib_drag or args.offset is None:
        print(f"\n[*] Crib-dragging '{args.known}' across ciphertext ...\n")
        crib_drag(cipher, known, args.top)
    else:
        key_frag = recover_key_at_offset(cipher, known, args.offset)
        print(f"\n[+] Key bytes at offset {args.offset}: {key_frag.hex()}  ({key_frag!r})")
        # Try to extend using assumed key period
        extended = extend_key(cipher, key_frag, args.offset)
        if extended:
            full_key = (extended * ((len(cipher) // len(extended)) + 2))[:len(cipher)]
            plaintext = xor(cipher, full_key)
            print(f"[+] Guessed key (period={len(extended)}): {extended.hex()}")
            print(f"[+] Decrypted: {plaintext.decode('utf-8', errors='replace')[:200]}")


if __name__ == "__main__":
    main()
