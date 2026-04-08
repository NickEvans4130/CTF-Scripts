#!/usr/bin/env python3
"""
Directory and file brute-forcer.
Sends GET requests for each wordlist entry, optionally appending extensions.
Multi-threaded with configurable status-code filtering.
Requires: requests
"""

import argparse
import queue
import sys
import threading
import time
from pathlib import Path
from urllib.parse import urljoin

try:
    import requests
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
except ImportError:
    print("[!] requests not installed: pip install requests", file=sys.stderr)
    sys.exit(1)

found_lock = threading.Lock()
counter_lock = threading.Lock()
stats = {"tried": 0, "found": 0}


def normalise_url(url: str) -> str:
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    if not url.endswith("/"):
        url += "/"
    return url


def try_path(session: requests.Session, base_url: str, path: str,
             good_codes: set[int], timeout: int,
             results: list, verbose: bool) -> None:
    url = urljoin(base_url, path)
    try:
        resp = session.get(url, timeout=timeout, allow_redirects=False,
                           verify=False)
        code = resp.status_code
        size = len(resp.content)

        with counter_lock:
            stats["tried"] += 1
            t = stats["tried"]
            if t % 100 == 0:
                print(f"\r[*] Tried {t} paths...", end="", flush=True)

        if code in good_codes:
            redirect = ""
            if code in (301, 302, 303, 307, 308):
                redirect = f"  -> {resp.headers.get('Location', '')}"
            line = f"[{code}] {url}  ({size}B){redirect}"
            with found_lock:
                print(f"\n{line}")
                stats["found"] += 1
                results.append({"code": code, "url": url, "size": size})
        elif verbose:
            print(f"\r[{code}] {url}", end="", flush=True)
    except requests.exceptions.Timeout:
        pass
    except requests.exceptions.ConnectionError:
        pass
    except Exception as e:
        if verbose:
            print(f"\r[!] {url}: {e}", end="", flush=True)


def worker(session, base_url, q, good_codes, timeout, results, verbose):
    while True:
        try:
            path = q.get(block=True, timeout=0.5)
        except queue.Empty:
            return
        try_path(session, base_url, path, good_codes, timeout, results, verbose)
        q.task_done()


def generate_paths(wordlist: Path, extensions: list[str]) -> list[str]:
    paths = []
    with open(wordlist, errors="ignore") as f:
        for line in f:
            word = line.strip().lstrip("/")
            if not word or word.startswith("#"):
                continue
            paths.append(word)
            for ext in extensions:
                paths.append(f"{word}.{ext.lstrip('.')}")
    return paths


def main():
    parser = argparse.ArgumentParser(description="Multi-threaded web directory and file brute-forcer")
    parser.add_argument("--url",      required=True, help="Target base URL")
    parser.add_argument("--wordlist", required=True, help="Wordlist file")
    parser.add_argument("--ext",      default="",
                        help="Comma-separated extensions to append (e.g. php,txt,bak)")
    parser.add_argument("--threads",  type=int, default=20,
                        help="Number of threads (default: 20)")
    parser.add_argument("--status",   default="200,204,301,302,307,401,403",
                        help="Comma-separated status codes to report (default: 200,204,301,302,307,401,403)")
    parser.add_argument("--timeout",  type=int, default=10,
                        help="Request timeout in seconds (default: 10)")
    parser.add_argument("--output",   help="Write results to file")
    parser.add_argument("--verbose",  action="store_true",
                        help="Show all responses, not just hits")
    parser.add_argument("--headers",  action="append", default=[], metavar="H:V",
                        help="Extra headers (repeatable): e.g. --headers 'Cookie: session=abc'")
    args = parser.parse_args()

    base_url   = normalise_url(args.url)
    wordlist   = Path(args.wordlist)
    extensions = [e.strip() for e in args.ext.split(",") if e.strip()]
    good_codes = {int(c.strip()) for c in args.status.split(",") if c.strip()}

    if not wordlist.exists():
        print(f"[!] Wordlist not found: {wordlist}", file=sys.stderr)
        sys.exit(1)

    session = requests.Session()
    session.headers.update({"User-Agent": "Mozilla/5.0 (CTF-Scanner)"})
    for h in args.headers:
        k, _, v = h.partition(":")
        session.headers[k.strip()] = v.strip()

    paths = generate_paths(wordlist, extensions)
    print(f"[*] Target:   {base_url}")
    print(f"[*] Paths:    {len(paths)} ({len(extensions)} extension(s) per word)")
    print(f"[*] Threads:  {args.threads}")
    print(f"[*] Codes:    {sorted(good_codes)}")
    print()

    q: queue.Queue = queue.Queue()
    for p in paths:
        q.put(p)

    results = []
    threads = [
        threading.Thread(target=worker,
                         args=(session, base_url, q, good_codes,
                               args.timeout, results, args.verbose),
                         daemon=True)
        for _ in range(args.threads)
    ]
    start = time.time()
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    elapsed = time.time() - start
    print(f"\n\n[*] Done in {elapsed:.1f}s  |  Tried: {stats['tried']}  |  Found: {stats['found']}")

    if args.output and results:
        with open(args.output, "w") as f:
            for r in results:
                f.write(f"{r['code']}  {r['url']}  {r['size']}B\n")
        print(f"[*] Results written to {args.output}")


if __name__ == "__main__":
    main()
