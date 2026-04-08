#!/usr/bin/env python3
"""
PNG IHDR CRC brute-forcer.
Finds the correct width and height for a PNG with a corrupted IHDR chunk
by brute-forcing all (w, h) pairs until CRC32 matches.
No external dependencies.
"""

import argparse
import struct
import sys
import zlib
from pathlib import Path


PNG_SIG = b"\x89PNG\r\n\x1a\n"

# IHDR layout (13 bytes):
#   width   : 4 bytes big-endian uint
#   height  : 4 bytes big-endian uint
#   bit_depth      : 1 byte
#   color_type     : 1 byte
#   compression    : 1 byte
#   filter_method  : 1 byte
#   interlace      : 1 byte


def read_ihdr(data: bytes) -> tuple[bytes, bytes, int]:
    """
    Parse the IHDR chunk.
    Returns (chunk_type+data, stored_crc_bytes, offset_of_length_field).
    """
    if not data.startswith(PNG_SIG):
        raise ValueError("Not a valid PNG (missing signature)")

    # First chunk starts at offset 8
    offset = 8
    length = struct.unpack(">I", data[offset:offset + 4])[0]
    chunk_type = data[offset + 4:offset + 8]

    if chunk_type != b"IHDR":
        raise ValueError("First chunk is not IHDR")

    chunk_data = data[offset + 8:offset + 8 + length]
    stored_crc = data[offset + 8 + length:offset + 8 + length + 4]

    return chunk_type + chunk_data, stored_crc, offset


def compute_ihdr_crc(chunk_type_and_data: bytes) -> bytes:
    return struct.pack(">I", zlib.crc32(chunk_type_and_data) & 0xFFFFFFFF)


def brute_force(data: bytes, max_dim: int) -> tuple[int, int] | None:
    """Brute-force (width, height) pairs to find one whose CRC32 matches the stored CRC."""
    chunk_type_data, stored_crc, offset = read_ihdr(data)

    # The fixed part of IHDR data (bit_depth through interlace) is bytes 8..12
    ihdr_suffix = chunk_type_data[8 + 4 + 4:]  # 5 bytes after width and height

    stored_crc_int = struct.unpack(">I", stored_crc)[0]

    print(f"[*] Stored CRC:  0x{stored_crc_int:08x}")
    print(f"[*] Current w/h: {struct.unpack('>II', chunk_type_data[4:12])}")
    print(f"[*] Searching (1, 1) .. ({max_dim}, {max_dim}) ...")

    for width in range(1, max_dim + 1):
        if width % 256 == 0:
            print(f"\r    Progress: width={width}/{max_dim}", end="", flush=True)
        for height in range(1, max_dim + 1):
            candidate = (
                b"IHDR"
                + struct.pack(">II", width, height)
                + ihdr_suffix
            )
            crc = zlib.crc32(candidate) & 0xFFFFFFFF
            if crc == stored_crc_int:
                print()
                return width, height
    print()
    return None


def patch_png(data: bytes, width: int, height: int) -> bytes:
    """Return a copy of data with IHDR width/height replaced and CRC recalculated."""
    patched = bytearray(data)

    offset = 8  # start of first chunk
    # width field is at offset+8, height at offset+12
    struct.pack_into(">I", patched, offset + 8, width)
    struct.pack_into(">I", patched, offset + 12, height)

    # Recalculate CRC over chunk_type + chunk_data (13 bytes)
    new_crc = zlib.crc32(bytes(patched[offset + 4:offset + 8 + 13])) & 0xFFFFFFFF
    struct.pack_into(">I", patched, offset + 8 + 13, new_crc)

    return bytes(patched)


def main():
    parser = argparse.ArgumentParser(
        description="Brute-force correct PNG dimensions by matching the IHDR CRC32"
    )
    parser.add_argument("file", help="Corrupted PNG file")
    parser.add_argument("--max-dim", type=int, default=4096,
                        help="Maximum dimension to search (default: 4096)")
    parser.add_argument("--output", help="Write fixed PNG to this path")
    args = parser.parse_args()

    path = Path(args.file)
    if not path.exists():
        print(f"[!] File not found: {path}", file=sys.stderr)
        sys.exit(1)

    data = path.read_bytes()

    try:
        result = brute_force(data, args.max_dim)
    except ValueError as e:
        print(f"[!] {e}", file=sys.stderr)
        sys.exit(1)

    if result is None:
        print(f"[-] No matching (width, height) found within 1..{args.max_dim}.")
        print("    Try increasing --max-dim or check that only dimensions are corrupted.")
        sys.exit(1)

    width, height = result
    print(f"[+] Found: width={width}  height={height}")

    out_path = Path(args.output) if args.output else path.with_stem(path.stem + "_fixed")
    fixed = patch_png(data, width, height)
    out_path.write_bytes(fixed)
    print(f"[+] Fixed PNG written to {out_path}")


if __name__ == "__main__":
    main()
