#!/usr/bin/env python3
"""
PNG/JPEG metadata extractor - wraps exiftool to dump all metadata fields.
"""

import argparse
import json
import subprocess
import sys
from pathlib import Path


INTERESTING_FIELDS = [
    "GPS", "Comment", "Software", "Author", "Creator", "Description",
    "Warning", "Thumbnail", "Profile", "Copyright", "UserComment",
]


def run_exiftool(path: Path, as_json: bool) -> None:
    cmd = ["exiftool"]
    if as_json:
        cmd.append("-json")
    cmd.append(str(path))

    try:
        result = subprocess.run(cmd, capture_output=True, text=True)
    except FileNotFoundError:
        print("[!] exiftool not found. Install with: sudo apt install exiftool", file=sys.stderr)
        sys.exit(1)

    if result.returncode != 0:
        print(f"[!] exiftool error: {result.stderr.strip()}", file=sys.stderr)
        sys.exit(1)

    if as_json:
        data = json.loads(result.stdout)
        print(json.dumps(data, indent=2))
    else:
        print(result.stdout)

    hits = [f for f in INTERESTING_FIELDS if f.lower() in result.stdout.lower()]
    if hits:
        print(f"[*] Interesting fields detected: {', '.join(hits)}")


def main():
    parser = argparse.ArgumentParser(description="Extract metadata from PNG/JPEG files using exiftool")
    parser.add_argument("file", help="Image file to analyse")
    parser.add_argument("--json", action="store_true", help="Output metadata as JSON")
    args = parser.parse_args()

    path = Path(args.file)
    if not path.exists():
        print(f"[!] File not found: {path}", file=sys.stderr)
        sys.exit(1)

    run_exiftool(path, args.json)


if __name__ == "__main__":
    main()
