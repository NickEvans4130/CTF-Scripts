#!/usr/bin/env python3
"""
Reusable SHA-1 length extension module.
Exposes padding calculation, forged message construction, and MAC computation.
Import this as a library or run standalone for quick use.
"""

import struct
import sys


# ── Core SHA-1 implementation with state injection ────────────────────────────

def _rotl32(n: int, b: int) -> int:
    return ((n << b) | (n >> (32 - b))) & 0xFFFFFFFF


def _sha1_compress(state: tuple[int, int, int, int, int], block: bytes) -> tuple:
    assert len(block) == 64
    w = list(struct.unpack('>16I', block))
    for i in range(16, 80):
        w.append(_rotl32(w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16], 1))

    a, b, c, d, e = state
    for i in range(80):
        if i < 20:
            f, k = (b & c) | (~b & d), 0x5A827999
        elif i < 40:
            f, k = b ^ c ^ d, 0x6ED9EBA1
        elif i < 60:
            f, k = (b & c) | (b & d) | (c & d), 0x8F1BBCDC
        else:
            f, k = b ^ c ^ d, 0xCA62C1D6
        f &= 0xFFFFFFFF
        temp = (_rotl32(a, 5) + f + e + k + w[i]) & 0xFFFFFFFF
        a, b, c, d, e = temp, a, _rotl32(b, 30), c, d

    h0, h1, h2, h3, h4 = state
    return ((h0 + a) & 0xFFFFFFFF, (h1 + b) & 0xFFFFFFFF,
            (h2 + c) & 0xFFFFFFFF, (h3 + d) & 0xFFFFFFFF,
            (h4 + e) & 0xFFFFFFFF)


def _sha1_pad(message_len: int) -> bytes:
    """Return the SHA-1 padding for a message of `message_len` bytes."""
    pad = b'\x80'
    pad += b'\x00' * ((55 - message_len) % 64)
    pad += struct.pack('>Q', message_len * 8)
    return pad


def _state_from_hex(mac_hex: str) -> tuple[int, int, int, int, int]:
    mac_bytes = bytes.fromhex(mac_hex)
    if len(mac_bytes) != 20:
        raise ValueError(f"SHA-1 MAC must be 20 bytes, got {len(mac_bytes)}")
    return struct.unpack('>5I', mac_bytes)


# ── Public API ─────────────────────────────────────────────────────────────────

def padding(secret_len: int, message_len: int) -> bytes:
    """
    Return the SHA-1 padding bytes that appear between the original message
    and any appended data in the forged message.

    Args:
        secret_len:  Length of the secret prefix in bytes.
        message_len: Length of the original known message in bytes.

    Returns:
        Padding bytes (0x80 + zero bytes + 8-byte big-endian bit length).
    """
    return _sha1_pad(secret_len + message_len)


def extend(mac_hex: str, original_message: bytes, secret_len: int,
           append_data: bytes) -> tuple[bytes, str]:
    """
    Perform a SHA-1 length extension.

    Args:
        mac_hex:          Hex string of H(secret || original_message).
        original_message: The known original message bytes.
        secret_len:       Length of the secret in bytes.
        append_data:      Data to append.

    Returns:
        (forged_message, forged_mac_hex)
        where forged_message = original_message + padding + append_data
        and   forged_mac_hex = H(secret || forged_message)
    """
    pad = padding(secret_len, len(original_message))
    forged_message = original_message + pad + append_data

    # The extended hash processes (append_data + final_pad) starting from
    # the MAC state, with a total length counter that includes the full prefix.
    state = _state_from_hex(mac_hex)
    total_prefix_len = secret_len + len(original_message) + len(pad)
    final_pad = _sha1_pad(total_prefix_len + len(append_data))

    data_to_hash = append_data + final_pad
    assert len(data_to_hash) % 64 == 0, "Extended data must be a multiple of 64 bytes"

    for i in range(0, len(data_to_hash), 64):
        state = _sha1_compress(state, data_to_hash[i:i + 64])

    forged_mac = struct.pack('>5I', *state).hex()
    return forged_message, forged_mac


# ── Standalone CLI ────────────────────────────────────────────────────────────

def main():
    import argparse

    parser = argparse.ArgumentParser(description="SHA-1 length extension - standalone tool")
    parser.add_argument("--mac", required=True,
                        help="Known SHA-1 MAC hex = SHA1(secret || original_msg)")
    parser.add_argument("--msg", required=True,
                        help="Original message (string, or hex with 0x prefix)")
    parser.add_argument("--secret-len", type=int, required=True, dest="secret_len",
                        help="Secret length in bytes")
    parser.add_argument("--append", required=True,
                        help="Data to append (string)")
    args = parser.parse_args()

    orig = bytes.fromhex(args.msg[2:]) if args.msg.startswith('0x') else args.msg.encode()
    app  = args.append.encode()

    pad = padding(args.secret_len, len(orig))

    print(f"[*] Original message:  {orig!r}")
    print(f"[*] Secret length:     {args.secret_len} bytes")
    print(f"[*] Padding (hex):     {pad.hex()}")
    print(f"[*] Append:            {app!r}")

    forged_msg, forged_mac = extend(args.mac, orig, args.secret_len, app)

    print(f"\n[+] Forged message (hex):  {forged_msg.hex()}")
    print(f"[+] Forged message (repr): {forged_msg!r}")
    print(f"[+] Forged MAC:            {forged_mac}")


if __name__ == "__main__":
    main()
