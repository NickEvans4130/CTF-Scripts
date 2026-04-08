#!/usr/bin/env python3
"""
Rainbow table lookup: queries hashes.com and crackstation.net APIs,
with optional local hash:plaintext CSV fallback.
"""

import argparse
import csv
import json
import sys
import time
import urllib.parse
import urllib.request
from pathlib import Path


# ── Online lookups ────────────────────────────────────────────────────────────

def lookup_hashes_com(hashes: list[str]) -> dict[str, str]:
    """Query hashes.com API (free, no key required for small batches)."""
    results = {}
    url = "https://hashes.com/en/api/identifier"
    data = urllib.parse.urlencode({
        "hashes[]": hashes,
        "hasType": "1"
    }).encode()
    req = urllib.request.Request(url, data=data, method='POST')
    req.add_header("Content-Type", "application/x-www-form-urlencoded")
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            body = json.loads(resp.read())
        for item in body.get("founds", []):
            results[item.get("hash", "").lower()] = item.get("plaintext", "")
    except Exception as e:
        print(f"[!] hashes.com error: {e}", file=sys.stderr)
    return results


def lookup_crackstation(hashes: list[str]) -> dict[str, str]:
    """Query CrackStation API (20 hashes per request)."""
    results = {}
    url = "https://crackstation.net/crack.js"
    payload = json.dumps({"hashes": hashes}).encode()
    req = urllib.request.Request(url, data=payload, method='POST')
    req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            body = json.loads(resp.read())
        for item in body:
            if item.get("cracked"):
                results[item["hash"].lower()] = item.get("password", "")
    except Exception as e:
        print(f"[!] crackstation error: {e}", file=sys.stderr)
    return results


def lookup_online(hashes: list[str], source: str = "both") -> dict[str, str]:
    results = {}
    if source in ("hashes.com", "both"):
        print("[*] Querying hashes.com ...")
        results.update(lookup_hashes_com(hashes))
    if source in ("crackstation", "both"):
        print("[*] Querying crackstation.net ...")
        # CrackStation: 20 hashes per request
        for i in range(0, len(hashes), 20):
            batch = hashes[i:i + 20]
            results.update(lookup_crackstation(batch))
            if i + 20 < len(hashes):
                time.sleep(0.5)
    return results


# ── Local CSV lookup ──────────────────────────────────────────────────────────

def lookup_local(hashes: list[str], db_path: Path) -> dict[str, str]:
    """Search a local CSV file formatted as 'hash,plaintext' per line."""
    hash_set = {h.lower() for h in hashes}
    results = {}
    with open(db_path, newline='', errors='ignore') as f:
        reader = csv.reader(f)
        for row in reader:
            if len(row) >= 2:
                h = row[0].lower().strip()
                if h in hash_set:
                    results[h] = row[1]
    return results


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Rainbow table lookup against online databases and local files")
    src = parser.add_mutually_exclusive_group(required=True)
    src.add_argument("hash",  nargs="?", help="Single hash to look up")
    src.add_argument("--file", help="File with one hash per line")

    parser.add_argument("--local-db", dest="local_db",
                        help="Local CSV file (hash,plaintext) to search first")
    parser.add_argument("--source", choices=["hashes.com", "crackstation", "both"],
                        default="both", help="Online source (default: both)")
    parser.add_argument("--offline", action="store_true",
                        help="Only use local database, no online queries")
    args = parser.parse_args()

    if args.file:
        hashes = [h.strip() for h in Path(args.file).read_text().splitlines() if h.strip()]
    else:
        hashes = [args.hash]

    print(f"[*] Looking up {len(hashes)} hash(es)")

    results: dict[str, str] = {}

    if args.local_db:
        db = Path(args.local_db)
        if db.exists():
            print(f"[*] Searching local DB: {db} ...")
            results.update(lookup_local(hashes, db))
        else:
            print(f"[!] Local DB not found: {db}")

    remaining = [h for h in hashes if h.lower() not in results]
    if remaining and not args.offline:
        results.update(lookup_online(remaining, args.source))

    print()
    found = 0
    for h in hashes:
        plaintext = results.get(h.lower())
        if plaintext is not None:
            print(f"[+] {h}  =>  {plaintext!r}")
            found += 1
        else:
            print(f"[-] {h}  =>  not found")

    print(f"\n[*] {found}/{len(hashes)} cracked")


if __name__ == "__main__":
    main()
