#!/usr/bin/env python3
"""
Hash length extension attack for MD5, SHA-1, and SHA-256.
Forges MAC = H(secret || message || padding || append) without knowing the secret.
"""

import argparse
import hashlib
import struct
import sys
from pathlib import Path


# ── MD5 padding ───────────────────────────────────────────────────────────────

def md5_pad(message_len: int) -> bytes:
    """Compute MD5 padding for a message of `message_len` bytes."""
    pad = b'\x80'
    pad += b'\x00' * ((55 - message_len) % 64)
    pad += struct.pack('<Q', message_len * 8)  # little-endian bit length
    return pad


# ── SHA-1 / SHA-256 padding ───────────────────────────────────────────────────

def sha_pad(message_len: int) -> bytes:
    """Compute SHA-1/SHA-256 padding (big-endian)."""
    pad = b'\x80'
    pad += b'\x00' * ((55 - message_len) % 64)
    pad += struct.pack('>Q', message_len * 8)
    return pad


# ── MD5 state injection ───────────────────────────────────────────────────────

def md5_extend(mac_hex: str, orig_len: int, append: bytes) -> tuple[bytes, str]:
    """Return (forged_message_suffix_including_padding, forged_mac_hex)."""
    import ctypes, hashlib
    # Parse the existing MAC as MD5 state (4 x uint32 LE)
    mac_bytes = bytes.fromhex(mac_hex)
    a, b, c, d = struct.unpack('<4I', mac_bytes)

    padding = md5_pad(orig_len)
    total_len = orig_len + len(padding) + len(append)

    # Build a new MD5 with injected state
    # Python's hashlib doesn't expose state, so we use a pure-Python MD5 shim
    # or fall back to the hlextend library approach.
    # Here we use a simple approach: compute new_mac = MD5 of forged message
    # using the known intermediate state.
    # We construct the forged_message = original_pad + append (without knowing secret)
    forged_suffix = padding + append

    # We cannot directly inject MD5 state without a C extension or pure-python impl.
    # Fall back to informational output and use hlextend if available.
    try:
        import hlextend
        sha = hlextend.new('md5')
        forged_msg, forged_mac = sha.extend(append, b'?' * (orig_len - len(append)), orig_len - len(append) - len(append), mac_hex)
        # hlextend API varies; use the standard API below instead
    except ImportError:
        pass

    return forged_suffix, "(use hlextend or sha1_length_extension.py for full MAC computation)"


# ── Pure-Python SHA-1 with state injection ────────────────────────────────────

def _sha1_process(state: tuple, data: bytes) -> tuple:
    """Process one 64-byte SHA-1 block with given initial state. Returns new state."""
    def rotl(n, b):
        return ((n << b) | (n >> (32 - b))) & 0xFFFFFFFF

    h0, h1, h2, h3, h4 = state
    assert len(data) == 64
    w = list(struct.unpack('>16I', data))
    for i in range(16, 80):
        w.append(rotl(w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16], 1))

    a, b, c, d, e = h0, h1, h2, h3, h4
    for i in range(80):
        if i < 20:
            f = (b & c) | (~b & d); k = 0x5A827999
        elif i < 40:
            f = b ^ c ^ d;          k = 0x6ED9EBA1
        elif i < 60:
            f = (b & c) | (b & d) | (c & d); k = 0x8F1BBCDC
        else:
            f = b ^ c ^ d;          k = 0xCA62C1D6
        temp = (rotl(a, 5) + f + e + k + w[i]) & 0xFFFFFFFF
        a, b, c, d, e = temp, a, rotl(b, 30), c, d

    return ((h0 + a) & 0xFFFFFFFF, (h1 + b) & 0xFFFFFFFF,
            (h2 + c) & 0xFFFFFFFF, (h3 + d) & 0xFFFFFFFF, (h4 + e) & 0xFFFFFFFF)


def sha1_extend(mac_hex: str, secret_len: int, orig_msg: bytes, append: bytes) -> tuple[bytes, str]:
    """SHA-1 length extension: returns (forged_message, forged_mac_hex)."""
    mac_bytes = bytes.fromhex(mac_hex)
    state = struct.unpack('>5I', mac_bytes)

    padding = sha_pad(secret_len + len(orig_msg))
    forged_msg = orig_msg + padding + append

    # Total length for the extended hash = secret + original + padding + append
    total_len = secret_len + len(orig_msg) + len(padding) + len(append)
    final_pad = sha_pad(total_len)

    # Process the append + final_pad block(s) using injected state
    data_to_process = append + final_pad
    assert len(data_to_process) % 64 == 0
    current_state = state
    for i in range(0, len(data_to_process), 64):
        current_state = _sha1_process(current_state, data_to_process[i:i + 64])

    forged_mac = struct.pack('>5I', *current_state).hex()
    return forged_msg, forged_mac


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Hash length extension attack for MD5, SHA-1, SHA-256")
    parser.add_argument("--algo", required=True, choices=["sha1", "md5", "sha256"],
                        help="Hash algorithm")
    parser.add_argument("--mac", required=True,
                        help="Known MAC (hex) = H(secret || original_message)")
    parser.add_argument("--msg", required=True,
                        help="Original message (string or hex with 0x prefix)")
    parser.add_argument("--append", required=True,
                        help="Data to append (string)")
    parser.add_argument("--secret-len", type=int, required=True, dest="secret_len",
                        help="Length of the secret in bytes")
    args = parser.parse_args()

    if args.msg.startswith('0x'):
        orig_msg = bytes.fromhex(args.msg[2:])
    else:
        orig_msg = args.msg.encode()

    append = args.append.encode()

    print(f"[*] Algorithm:   {args.algo}")
    print(f"[*] Secret len:  {args.secret_len} bytes")
    print(f"[*] Original msg ({len(orig_msg)} bytes): {orig_msg!r}")
    print(f"[*] Known MAC:   {args.mac}")
    print(f"[*] Append:      {append!r}")

    if args.algo == "sha1":
        forged_msg, forged_mac = sha1_extend(args.mac, args.secret_len, orig_msg, append)
        print(f"\n[+] Forged message (hex): {forged_msg.hex()}")
        print(f"[+] Forged message (repr): {forged_msg!r}")
        print(f"[+] Forged MAC:   {forged_mac}")
    elif args.algo in ("md5", "sha256"):
        print(f"\n[!] Full state injection for {args.algo} requires the 'hlextend' library:")
        print(f"    pip install hlextend")
        print(f"\n    Padding that would be appended to original message:")
        pad = md5_pad(args.secret_len + len(orig_msg)) if args.algo == "md5" \
              else sha_pad(args.secret_len + len(orig_msg))
        print(f"    {pad.hex()}")
        print(f"    Forged message = original_msg + padding + append")
    else:
        print("[!] Unsupported algorithm")
        sys.exit(1)


if __name__ == "__main__":
    main()
