#!/usr/bin/env python3
"""
Memory dump string extractor and pattern grep.
Extracts printable strings and searches for flags, URLs, credentials, etc.
"""

import argparse
import re
import sys
from pathlib import Path


# ── Built-in patterns ─────────────────────────────────────────────────────────

PATTERNS = {
    "flag":  r"(?:flag|ctf|htb|picoctf|thm)\{[^}]{1,200}\}",
    "url":   r"https?://[^\s\"'<>]{4,200}",
    "email": r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}",
    "ip":    r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
    "cred":  r"(?:password|passwd|pwd|secret|token|api[_\-]?key)\s*[=:]\s*\S+",
}


def extract_strings(data: bytes, min_len: int) -> list[tuple[int, str]]:
    """Extract printable ASCII strings of at least min_len characters."""
    results = []
    pattern = re.compile(rb"[ -~]{" + str(min_len).encode() + rb",}")
    for m in pattern.finditer(data):
        results.append((m.start(), m.group().decode("ascii", errors="replace")))
    return results


def search_patterns(strings: list[tuple[int, str]], pattern_re: str) -> list[tuple[int, str]]:
    rx = re.compile(pattern_re, re.IGNORECASE)
    hits = []
    for offset, s in strings:
        for m in rx.finditer(s):
            hits.append((offset, m.group()))
    return hits


def main():
    parser = argparse.ArgumentParser(description="Extract strings and search patterns in memory dumps")
    parser.add_argument("file", help="Memory dump file")
    parser.add_argument("--pattern", help="Custom regex pattern to search for")
    parser.add_argument("--preset", choices=list(PATTERNS.keys()),
                        help="Use a built-in pattern preset")
    parser.add_argument("--min-len", type=int, default=6,
                        help="Minimum string length (default: 6)")
    parser.add_argument("--all-strings", action="store_true",
                        help="Print all extracted strings (not just pattern matches)")
    parser.add_argument("--output", help="Write results to file")
    args = parser.parse_args()

    path = Path(args.file)
    if not path.exists():
        print(f"[!] File not found: {path}", file=sys.stderr)
        sys.exit(1)

    print(f"[*] Loading {path} ({path.stat().st_size:,} bytes) ...")
    data = path.read_bytes()

    print(f"[*] Extracting strings (min length: {args.min_len}) ...")
    strings = extract_strings(data, args.min_len)
    print(f"[*] {len(strings)} strings found")

    lines = []

    if args.all_strings:
        for offset, s in strings:
            lines.append(f"0x{offset:08x}  {s}")

    search_rx = None
    if args.pattern:
        search_rx = args.pattern
        label = "custom pattern"
    elif args.preset:
        search_rx = PATTERNS[args.preset]
        label = args.preset

    if search_rx is None and not args.all_strings:
        # Default: search all built-in patterns
        for name, rx in PATTERNS.items():
            hits = search_patterns(strings, rx)
            if hits:
                print(f"\n[+] {name.upper()} matches ({len(hits)}):")
                for offset, match in hits:
                    print(f"    0x{offset:08x}  {match}")
                    lines.append(f"[{name}] 0x{offset:08x}  {match}")
    elif search_rx:
        hits = search_patterns(strings, search_rx)
        print(f"\n[+] Matches for '{label}' ({len(hits)}):")
        for offset, match in hits:
            print(f"    0x{offset:08x}  {match}")
            lines.append(f"0x{offset:08x}  {match}")
    else:
        for line in lines:
            print(line)

    if args.output and lines:
        Path(args.output).write_text("\n".join(lines) + "\n")
        print(f"\n[*] Results written to {args.output}")


if __name__ == "__main__":
    main()
