#!/usr/bin/env python3
"""
Disk image file system walker using pytsk3.
Lists and optionally extracts files from raw disk images (FAT, ext2/3/4, NTFS).
Requires: pytsk3, pytsk3 depends on libtsk (sudo apt install libtsk-dev)
"""

import argparse
import sys
from pathlib import Path

try:
    import pytsk3
except ImportError:
    print("[!] pytsk3 not installed: pip install pytsk3", file=sys.stderr)
    print("    Also requires libtsk: sudo apt install libtsk-dev", file=sys.stderr)
    sys.exit(1)


def open_image(path: Path):
    try:
        img = pytsk3.Img_Info(str(path))
    except Exception as e:
        print(f"[!] Could not open image: {e}", file=sys.stderr)
        sys.exit(1)
    try:
        fs = pytsk3.FS_Info(img)
    except Exception as e:
        print(f"[!] Could not detect filesystem: {e}", file=sys.stderr)
        sys.exit(1)
    return img, fs


def walk_directory(fs, directory, prefix: str, pattern: str | None,
                   files: list, verbose: bool) -> None:
    try:
        for entry in directory:
            name = entry.info.name.name.decode("utf-8", errors="replace")
            if name in (".", ".."):
                continue
            full_path = f"{prefix}/{name}"
            if verbose or (pattern and pattern.lower() in name.lower()):
                meta = entry.info.meta
                size = meta.size if meta else 0
                print(f"  {full_path}  ({size} bytes)")
            files.append((full_path, entry))
            if entry.info.meta and entry.info.meta.type == pytsk3.TSK_FS_META_TYPE_DIR:
                try:
                    sub_dir = entry.as_directory()
                    walk_directory(fs, sub_dir, full_path, pattern, files, verbose)
                except Exception:
                    pass
    except Exception:
        pass


def extract_file(fs, entry, dest: Path) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    meta = entry.info.meta
    if not meta:
        return
    size = meta.size
    try:
        f = entry.read_random(0, size)
        dest.write_bytes(f)
        print(f"[+] Extracted: {dest}  ({size} bytes)")
    except Exception as e:
        print(f"[!] Failed to extract: {e}")


def main():
    parser = argparse.ArgumentParser(description="Walk file system in a raw disk image")
    parser.add_argument("image", help="Disk image file (.img, .dd, .raw)")
    parser.add_argument("--list", action="store_true",
                        help="List all files in the image")
    parser.add_argument("--pattern", help="Only show files matching this substring")
    parser.add_argument("--extract", metavar="PATH",
                        help="Extract a specific file path from the image")
    parser.add_argument("--extract-all", metavar="DIR",
                        help="Extract all files to this directory")
    args = parser.parse_args()

    path = Path(args.image)
    if not path.exists():
        print(f"[!] File not found: {path}", file=sys.stderr)
        sys.exit(1)

    img, fs = open_image(path)
    root = fs.open_dir("/")

    files: list = []
    verbose = args.list or args.pattern is not None
    walk_directory(fs, root, "", args.pattern, files, verbose)

    if not verbose:
        print(f"[*] {len(files)} entries found. Use --list to display them.")

    if args.extract:
        target = args.extract.lstrip("/")
        matches = [(p, e) for p, e in files if p.lstrip("/") == target]
        if not matches:
            print(f"[!] Path not found: {args.extract}")
        else:
            _, entry = matches[0]
            extract_file(fs, entry, Path(target))

    if args.extract_all:
        out_dir = Path(args.extract_all)
        for fpath, entry in files:
            meta = entry.info.meta
            if meta and meta.type == pytsk3.TSK_FS_META_TYPE_REG:
                extract_file(fs, entry, out_dir / fpath.lstrip("/"))


if __name__ == "__main__":
    main()
