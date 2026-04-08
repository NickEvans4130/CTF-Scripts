#!/usr/bin/env python3
"""
File magic byte identifier and header fixer.
No external dependencies - uses a built-in signature table.
"""

import argparse
import sys
from pathlib import Path


# (name, hex_signature, extension, offset)
SIGNATURES = [
    ("PNG",          "89504e470d0a1a0a", ".png",  0),
    ("JPEG",         "ffd8ff",           ".jpg",  0),
    ("GIF87a",       "474946383761",     ".gif",  0),
    ("GIF89a",       "474946383961",     ".gif",  0),
    ("BMP",          "424d",             ".bmp",  0),
    ("TIFF (LE)",    "49492a00",         ".tiff", 0),
    ("TIFF (BE)",    "4d4d002a",         ".tiff", 0),
    ("PDF",          "25504446",         ".pdf",  0),
    ("ZIP",          "504b0304",         ".zip",  0),
    ("ZIP empty",    "504b0506",         ".zip",  0),
    ("RAR4",         "526172211a0700",   ".rar",  0),
    ("RAR5",         "526172211a070100", ".rar",  0),
    ("7-Zip",        "377abcaf271c",     ".7z",   0),
    ("Gzip",         "1f8b",             ".gz",   0),
    ("Bzip2",        "425a68",           ".bz2",  0),
    ("XZ",           "fd377a585a00",     ".xz",   0),
    ("Tar",          "7573746172",       ".tar",  257),
    ("ELF",          "7f454c46",         ".elf",  0),
    ("PE/EXE",       "4d5a",             ".exe",  0),
    ("Mach-O 32",    "feedface",         "",      0),
    ("Mach-O 64",    "feedfacf",         "",      0),
    ("Class (Java)", "cafebabe",         ".class",0),
    ("SQLite",       "53514c69746520666f726d617420330",  ".db", 0),
    ("MP3",          "494433",           ".mp3",  0),
    ("MP3 (sync)",   "fffb",             ".mp3",  0),
    ("WAV",          "52494646",         ".wav",  0),
    ("OGG",          "4f676753",         ".ogg",  0),
    ("FLAC",         "664c6143",         ".flac", 0),
    ("MP4/ISO",      "66747970",         ".mp4",  4),
    ("AVI",          "41564920",         ".avi",  8),
    ("DOCX/XLSX",    "504b0304",         ".docx", 0),  # same as ZIP
    ("XML",          "3c3f786d6c",       ".xml",  0),
    ("HTML",         "3c68746d6c",       ".html", 0),
    ("Zlib",         "789c",             ".zlib", 0),
]

KNOWN_HEADERS: dict[str, bytes] = {
    "png":  bytes.fromhex("89504e470d0a1a0a"),
    "jpeg": bytes.fromhex("ffd8ffe0"),
    "jpg":  bytes.fromhex("ffd8ffe0"),
    "gif":  bytes.fromhex("47494638396100010001"),
    "zip":  bytes.fromhex("504b0304"),
    "pdf":  bytes.fromhex("255044462d"),
    "elf":  bytes.fromhex("7f454c46"),
    "gz":   bytes.fromhex("1f8b"),
    "bmp":  bytes.fromhex("424d"),
}


def identify(data: bytes) -> list[str]:
    matches = []
    for name, sig_hex, ext, offset in SIGNATURES:
        sig = bytes.fromhex(sig_hex)
        if data[offset:offset + len(sig)] == sig:
            matches.append(f"{name}  ({ext or 'no ext'})  offset={offset}")
    return matches


def fix_header(path: Path, expected: str, dry_run: bool) -> None:
    key = expected.lower().lstrip(".")
    if key not in KNOWN_HEADERS:
        print(f"[!] Unknown format '{expected}'. Known: {', '.join(KNOWN_HEADERS)}")
        sys.exit(1)

    header = KNOWN_HEADERS[key]
    data = bytearray(path.read_bytes())
    current = bytes(data[:len(header)])

    if current == header:
        print("[*] Header already correct, no fix needed.")
        return

    print(f"[*] Current header:  {current.hex()}")
    print(f"[*] Expected header: {header.hex()}")

    if dry_run:
        print("[*] Dry run - no changes written.")
        return

    data[:len(header)] = header
    path.write_bytes(bytes(data))
    print(f"[+] Header fixed in-place: {path}")


def main():
    parser = argparse.ArgumentParser(description="Identify file type from magic bytes and optionally fix header")
    parser.add_argument("file", help="File to inspect")
    parser.add_argument("--fix", action="store_true",
                        help="Overwrite file header with the expected magic bytes")
    parser.add_argument("--expected", metavar="FORMAT",
                        help="Expected format for --fix (e.g. png, jpg, zip, elf)")
    parser.add_argument("--dry-run", action="store_true",
                        help="Show what --fix would do without writing")
    args = parser.parse_args()

    path = Path(args.file)
    if not path.exists():
        print(f"[!] File not found: {path}", file=sys.stderr)
        sys.exit(1)

    data = path.read_bytes()
    print(f"[*] File: {path}  ({len(data):,} bytes)")
    print(f"[*] First 16 bytes: {data[:16].hex()}")
    print()

    matches = identify(data)
    if matches:
        print("[+] Identified as:")
        for m in matches:
            print(f"    {m}")
    else:
        print("[-] No matching signature found.")

    if args.fix:
        if not args.expected:
            print("[!] --fix requires --expected FORMAT", file=sys.stderr)
            sys.exit(1)
        print()
        fix_header(path, args.expected, args.dry_run)


if __name__ == "__main__":
    main()
