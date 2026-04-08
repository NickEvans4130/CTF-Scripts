#!/usr/bin/env python3
"""
Filesystem timestamps forensic analyser.
Reads NTFS MFT records or ext4 inodes from a disk image and builds a timeline.
Requires: pytsk3 (pip install pytsk3), libtsk (sudo apt install libtsk-dev)
"""

import argparse
import csv
import sys
from datetime import datetime, timezone
from pathlib import Path

try:
    import pytsk3
    PYTSK3_AVAILABLE = True
except ImportError:
    PYTSK3_AVAILABLE = False


# ── Timestamp helpers ─────────────────────────────────────────────────────────

def ts_to_dt(ts: int) -> str:
    """Convert a POSIX timestamp (seconds) to a UTC datetime string."""
    if ts <= 0:
        return "N/A"
    try:
        return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    except (OSError, OverflowError):
        return "N/A"


def windows_filetime_to_dt(ft: int) -> str:
    """Convert Windows FILETIME (100-ns intervals since 1601-01-01) to UTC string."""
    if ft == 0:
        return "N/A"
    try:
        posix = (ft - 116444736000000000) / 10_000_000
        return datetime.fromtimestamp(posix, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    except Exception:
        return "N/A"


# ── pytsk3 filesystem walk ────────────────────────────────────────────────────

def get_timestamps_pytsk3(image_path: Path) -> list[dict]:
    if not PYTSK3_AVAILABLE:
        print("[!] pytsk3 not installed: pip install pytsk3", file=sys.stderr)
        sys.exit(1)

    img = pytsk3.Img_Info(str(image_path))
    try:
        fs = pytsk3.FS_Info(img)
    except Exception as e:
        print(f"[!] Could not open filesystem: {e}", file=sys.stderr)
        sys.exit(1)

    entries = []

    def walk(directory, path_prefix):
        try:
            for entry in directory:
                name = entry.info.name.name.decode("utf-8", errors="replace")
                if name in (".", ".."):
                    continue
                meta = entry.info.meta
                if meta is None:
                    continue
                full_path = f"{path_prefix}/{name}"
                entries.append({
                    "path":   full_path,
                    "type":   "DIR" if meta.type == pytsk3.TSK_FS_META_TYPE_DIR else "FILE",
                    "size":   meta.size,
                    "mtime":  ts_to_dt(meta.mtime),
                    "atime":  ts_to_dt(meta.atime),
                    "crtime": ts_to_dt(meta.crtime) if hasattr(meta, "crtime") else "N/A",
                    "ctime":  ts_to_dt(meta.ctime),
                })
                if meta.type == pytsk3.TSK_FS_META_TYPE_DIR:
                    try:
                        walk(entry.as_directory(), full_path)
                    except Exception:
                        pass
        except Exception:
            pass

    walk(fs.open_dir("/"), "")
    return entries


# ── Fallback: stat() on local files ──────────────────────────────────────────

def get_timestamps_local(path: Path) -> list[dict]:
    """Walk a local directory and collect timestamps. Useful for mounted images."""
    entries = []
    for child in sorted(path.rglob("*")):
        st = child.stat()
        entries.append({
            "path":   str(child.relative_to(path)),
            "type":   "DIR" if child.is_dir() else "FILE",
            "size":   st.st_size,
            "mtime":  ts_to_dt(int(st.st_mtime)),
            "atime":  ts_to_dt(int(st.st_atime)),
            "crtime": ts_to_dt(int(st.st_ctime)),  # ctime on Unix = metadata change time
            "ctime":  "N/A",
        })
    return entries


# ── Output ────────────────────────────────────────────────────────────────────

def print_timeline(entries: list[dict]) -> None:
    # Sort by mtime
    def sort_key(e):
        return e["mtime"] if e["mtime"] != "N/A" else "9999"

    print(f"\n{'mtime':<26} {'type':<5} {'size':>10}  path")
    print("-" * 80)
    for e in sorted(entries, key=sort_key):
        print(f"{e['mtime']:<26} {e['type']:<5} {e['size']:>10}  {e['path']}")


def write_csv(entries: list[dict], out: Path) -> None:
    fieldnames = ["path", "type", "size", "mtime", "atime", "crtime", "ctime"]
    with open(out, "w", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(entries)
    print(f"[*] Timeline written to {out}")


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Forensic timestamp analyser for disk images or directories")
    parser.add_argument("path", help="Disk image file or mounted directory path")
    parser.add_argument("--format", choices=["image", "dir"], default="image",
                        help="Input type: 'image' uses pytsk3, 'dir' uses stat() (default: image)")
    parser.add_argument("--timeline", action="store_true",
                        help="Print sorted timeline to stdout")
    parser.add_argument("--output", help="Write timeline to CSV file")
    args = parser.parse_args()

    target = Path(args.path)
    if not target.exists():
        print(f"[!] Path not found: {target}", file=sys.stderr)
        sys.exit(1)

    print(f"[*] Collecting timestamps from {target} ...")

    if args.format == "image":
        entries = get_timestamps_pytsk3(target)
    else:
        entries = get_timestamps_local(target)

    print(f"[*] {len(entries)} filesystem entries collected")

    if args.timeline or not args.output:
        print_timeline(entries)

    if args.output:
        write_csv(entries, Path(args.output))


if __name__ == "__main__":
    main()
