#!/usr/bin/env python3
"""
Recursive nested archive extractor.
Handles zip, tar (gz/bz2/xz), 7z, and rar with optional password lists.
"""

import argparse
import os
import shutil
import sys
import tarfile
import zipfile
from pathlib import Path

try:
    import py7zr
    SEVENZ_AVAILABLE = True
except ImportError:
    SEVENZ_AVAILABLE = False

try:
    import rarfile
    RAR_AVAILABLE = True
except ImportError:
    RAR_AVAILABLE = False

ARCHIVE_EXTS = {".zip", ".tar", ".gz", ".bz2", ".xz", ".tgz", ".tbz2", ".7z", ".rar"}


def is_archive(path: Path) -> bool:
    return path.suffix.lower() in ARCHIVE_EXTS or tarfile.is_tarfile(str(path))


def load_passwords(path: Path | None) -> list[str]:
    if path is None:
        return [""]
    with open(path, "r", errors="ignore") as fh:
        passwords = [l.rstrip("\n\r") for l in fh]
    return passwords or [""]


def try_extract_zip(path: Path, dest: Path, passwords: list[str]) -> bool:
    try:
        with zipfile.ZipFile(path) as zf:
            for pwd in passwords:
                try:
                    zf.extractall(dest, pwd=pwd.encode() if pwd else None)
                    if pwd:
                        print(f"      [+] ZIP password: {pwd!r}")
                    return True
                except (RuntimeError, Exception):
                    continue
    except zipfile.BadZipFile:
        pass
    return False


def try_extract_tar(path: Path, dest: Path) -> bool:
    try:
        with tarfile.open(path) as tf:
            tf.extractall(dest)
        return True
    except tarfile.TarError:
        return False


def try_extract_7z(path: Path, dest: Path, passwords: list[str]) -> bool:
    if not SEVENZ_AVAILABLE:
        return False
    for pwd in passwords:
        try:
            with py7zr.SevenZipFile(path, "r", password=pwd or None) as sz:
                sz.extractall(dest)
            if pwd:
                print(f"      [+] 7z password: {pwd!r}")
            return True
        except Exception:
            continue
    return False


def try_extract_rar(path: Path, dest: Path, passwords: list[str]) -> bool:
    if not RAR_AVAILABLE:
        return False
    for pwd in passwords:
        try:
            with rarfile.RarFile(path) as rf:
                rf.extractall(dest, pwd=pwd or None)
            if pwd:
                print(f"      [+] RAR password: {pwd!r}")
            return True
        except Exception:
            continue
    return False


def extract(path: Path, dest: Path, passwords: list[str]) -> bool:
    dest.mkdir(parents=True, exist_ok=True)
    ext = path.suffix.lower()

    if ext == ".zip" or zipfile.is_zipfile(str(path)):
        return try_extract_zip(path, dest, passwords)
    if ext in {".tar", ".gz", ".bz2", ".xz", ".tgz", ".tbz2"} or tarfile.is_tarfile(str(path)):
        return try_extract_tar(path, dest)
    if ext == ".7z":
        return try_extract_7z(path, dest, passwords)
    if ext == ".rar":
        return try_extract_rar(path, dest, passwords)
    return False


def walk(path: Path, dest: Path, passwords: list[str], depth: int = 0) -> None:
    indent = "  " * depth
    print(f"{indent}[>] {path.name}")

    if not is_archive(path):
        print(f"{indent}    (not an archive, skipping)")
        return

    ok = extract(path, dest, passwords)
    if not ok:
        print(f"{indent}    [!] Failed to extract (wrong password or unsupported format)")
        return

    print(f"{indent}    Extracted to: {dest}")

    for child in sorted(dest.rglob("*")):
        if child.is_file() and is_archive(child):
            child_dest = child.parent / (child.stem + "_extracted")
            walk(child, child_dest, passwords, depth + 1)


def main():
    parser = argparse.ArgumentParser(description="Recursively extract nested archives")
    parser.add_argument("archive", help="Top-level archive to unpack")
    parser.add_argument("--passwords", help="File containing passwords to try at each layer")
    parser.add_argument("--output", default="./nested_extracted",
                        help="Root output directory (default: ./nested_extracted)")
    args = parser.parse_args()

    path = Path(args.archive)
    if not path.exists():
        print(f"[!] File not found: {path}", file=sys.stderr)
        sys.exit(1)

    passwords = load_passwords(Path(args.passwords) if args.passwords else None)
    print(f"[*] Passwords loaded: {len(passwords)}")

    out = Path(args.output)
    out.mkdir(parents=True, exist_ok=True)

    walk(path, out / path.stem, passwords)
    print(f"\n[*] Done. Output: {out}")


if __name__ == "__main__":
    main()
