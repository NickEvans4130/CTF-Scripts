#!/usr/bin/env python3
"""
Binwalk wrapper with recursive file carving.
"""

import argparse
import subprocess
import sys
from pathlib import Path


def run_binwalk(target: Path, output_dir: Path, extract: bool = True) -> list[Path]:
    """Run binwalk on target, return list of extracted files."""
    cmd = ["binwalk"]
    if extract:
        cmd += ["--extract", "--directory", str(output_dir)]
    cmd.append(str(target))

    try:
        result = subprocess.run(cmd, capture_output=False, text=True)
    except FileNotFoundError:
        print("[!] binwalk not found. Install with: sudo apt install binwalk", file=sys.stderr)
        sys.exit(1)

    if result.returncode != 0:
        print(f"[!] binwalk returned exit code {result.returncode}")

    # Collect anything binwalk extracted into output_dir
    extracted = []
    if extract and output_dir.exists():
        for f in output_dir.rglob("*"):
            if f.is_file() and f != target:
                extracted.append(f)
    return extracted


def recursive_extract(path: Path, output_dir: Path, depth: int, max_depth: int,
                      visited: set) -> None:
    if depth > max_depth:
        print(f"[!] Max depth {max_depth} reached, stopping.")
        return

    real = path.resolve()
    if real in visited:
        return
    visited.add(real)

    indent = "  " * depth
    print(f"{indent}[+] Analysing: {path.name}")

    level_out = output_dir / f"depth_{depth}_{path.stem}"
    level_out.mkdir(parents=True, exist_ok=True)

    extracted = run_binwalk(path, level_out)
    print(f"{indent}    Extracted {len(extracted)} file(s)")

    for child in extracted:
        recursive_extract(child, output_dir, depth + 1, max_depth, visited)


def main():
    parser = argparse.ArgumentParser(description="Binwalk wrapper with recursive file carving")
    parser.add_argument("file", help="File to analyse")
    parser.add_argument("--recursive", action="store_true",
                        help="Recursively run binwalk on extracted files")
    parser.add_argument("--depth", type=int, default=5,
                        help="Max recursion depth (default: 5)")
    parser.add_argument("--output", default="./binwalk_extracted",
                        help="Output directory (default: ./binwalk_extracted)")
    parser.add_argument("--no-extract", action="store_true",
                        help="Only scan signatures, do not extract")
    args = parser.parse_args()

    path = Path(args.file)
    if not path.exists():
        print(f"[!] File not found: {path}", file=sys.stderr)
        sys.exit(1)

    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)
    extract = not args.no_extract

    if args.recursive and extract:
        recursive_extract(path, output_dir, depth=0, max_depth=args.depth, visited=set())
    else:
        run_binwalk(path, output_dir, extract=extract)


if __name__ == "__main__":
    main()
