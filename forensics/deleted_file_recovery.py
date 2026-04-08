#!/usr/bin/env python3
"""
Deleted file recovery from raw disk images via file signature carving.
Scans for known file headers/footers and extracts embedded files.
"""

import argparse
import sys
from pathlib import Path


# (name, header_hex, footer_hex or None, max_size_bytes)
SIGNATURES = {
    "jpeg": ("ffd8ff",   "ffd9",         20 * 1024 * 1024),
    "png":  ("89504e47", "49454e44ae426082", 20 * 1024 * 1024),
    "gif":  ("47494638", "003b",         10 * 1024 * 1024),
    "pdf":  ("25504446", "2525454f46",   50 * 1024 * 1024),
    "zip":  ("504b0304", "504b0506",     100 * 1024 * 1024),
    "mp3":  ("494433",   None,           10 * 1024 * 1024),
    "elf":  ("7f454c46", None,           10 * 1024 * 1024),
    "exe":  ("4d5a",     None,           10 * 1024 * 1024),
    "gz":   ("1f8b08",   None,           50 * 1024 * 1024),
    "bmp":  ("424d",     None,           20 * 1024 * 1024),
    "docx": ("504b0304", "504b0506",     50 * 1024 * 1024),
}

BLOCK = 512  # scan granularity in bytes


def carve(data: bytes, name: str, header: bytes, footer: bytes | None,
          max_size: int, out_dir: Path, count: list) -> None:
    pos = 0
    found = 0
    while pos < len(data):
        idx = data.find(header, pos)
        if idx == -1:
            break

        if footer:
            end = data.find(footer, idx + len(header))
            if end == -1 or end - idx > max_size:
                pos = idx + 1
                continue
            end += len(footer)
        else:
            end = min(idx + max_size, len(data))

        chunk = data[idx:end]
        out_file = out_dir / f"{name}_{count[0]:04d}.{name}"
        out_file.write_bytes(chunk)
        found += 1
        count[0] += 1
        print(f"  [+] {name.upper()} @ 0x{idx:08x}  ({len(chunk):,} bytes) -> {out_file.name}")
        pos = end

    if not found:
        print(f"  [-] {name.upper()}: none found")


def main():
    parser = argparse.ArgumentParser(description="Recover deleted files from raw disk images via file carving")
    parser.add_argument("image", help="Raw disk image file")
    parser.add_argument("--output-dir", default="./recovered",
                        help="Directory to write recovered files (default: ./recovered)")
    parser.add_argument("--types", default=",".join(SIGNATURES.keys()),
                        help=f"Comma-separated list of file types to carve (default: all). "
                             f"Available: {', '.join(SIGNATURES.keys())}")
    args = parser.parse_args()

    path = Path(args.image)
    if not path.exists():
        print(f"[!] File not found: {path}", file=sys.stderr)
        sys.exit(1)

    out_dir = Path(args.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    types = [t.strip().lower() for t in args.types.split(",")]
    invalid = [t for t in types if t not in SIGNATURES]
    if invalid:
        print(f"[!] Unknown types: {', '.join(invalid)}", file=sys.stderr)
        sys.exit(1)

    print(f"[*] Loading {path} ({path.stat().st_size:,} bytes) ...")
    data = path.read_bytes()
    print(f"[*] Carving for: {', '.join(types)}\n")

    counter = [0]
    for name in types:
        header_hex, footer_hex, max_size = SIGNATURES[name]
        header = bytes.fromhex(header_hex)
        footer = bytes.fromhex(footer_hex) if footer_hex else None
        carve(data, name, header, footer, max_size, out_dir, counter)

    print(f"\n[*] Total recovered: {counter[0]} file(s) -> {out_dir}")


if __name__ == "__main__":
    main()
