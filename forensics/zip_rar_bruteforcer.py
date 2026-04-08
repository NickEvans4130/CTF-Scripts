#!/usr/bin/env python3
"""
ZIP/RAR password brute-forcer - wordlist and charset modes, multi-threaded.
"""

import argparse
import itertools
import queue
import string
import sys
import threading
import zipfile
from pathlib import Path

try:
    import rarfile
    RAR_AVAILABLE = True
except ImportError:
    RAR_AVAILABLE = False


CHARSETS = {
    "digits":    string.digits,
    "lower":     string.ascii_lowercase,
    "upper":     string.ascii_uppercase,
    "alpha":     string.ascii_letters,
    "alphanum":  string.ascii_letters + string.digits,
    "printable": string.printable.strip(),
}

found_event = threading.Event()
result_lock = threading.Lock()
found_password: list[str] = []


# ── Archive helpers ────────────────────────────────────────────────────────────

def try_zip(path: Path, password: str) -> bool:
    try:
        with zipfile.ZipFile(path) as zf:
            zf.extractall(path="/dev/null", pwd=password.encode())
        return True
    except (RuntimeError, zipfile.BadZipFile, Exception):
        return False


def try_rar(path: Path, password: str) -> bool:
    try:
        with rarfile.RarFile(path) as rf:
            rf.extractall(path="/dev/null", pwd=password)
        return True
    except Exception:
        return False


def try_password(path: Path, is_rar: bool, password: str) -> bool:
    return try_rar(path, password) if is_rar else try_zip(path, password)


# ── Worker ────────────────────────────────────────────────────────────────────

def worker(path: Path, is_rar: bool, q: queue.Queue, counter: list) -> None:
    while not found_event.is_set():
        try:
            password = q.get(timeout=0.1)
        except queue.Empty:
            return

        with result_lock:
            counter[0] += 1
            if counter[0] % 1000 == 0:
                print(f"\r[*] Tried {counter[0]} passwords...", end="", flush=True)

        if try_password(path, is_rar, password):
            with result_lock:
                found_password.append(password)
            found_event.set()
            return

        q.task_done()


def launch_workers(path: Path, is_rar: bool, password_iter, n_threads: int) -> str | None:
    q: queue.Queue = queue.Queue(maxsize=n_threads * 4)
    counter = [0]

    threads = [
        threading.Thread(target=worker, args=(path, is_rar, q, counter), daemon=True)
        for _ in range(n_threads)
    ]
    for t in threads:
        t.start()

    for pwd in password_iter:
        if found_event.is_set():
            break
        q.put(pwd)

    found_event.wait(timeout=0.5)
    for t in threads:
        t.join(timeout=1)

    print()
    return found_password[0] if found_password else None


# ── Password generators ────────────────────────────────────────────────────────

def wordlist_gen(path: Path):
    with open(path, "r", errors="ignore") as fh:
        for line in fh:
            yield line.rstrip("\n\r")


def charset_gen(charset: str, min_len: int, max_len: int):
    for length in range(min_len, max_len + 1):
        for combo in itertools.product(charset, repeat=length):
            yield "".join(combo)


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Brute-force ZIP/RAR archive passwords")
    parser.add_argument("archive", help="Archive file to crack")

    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--wordlist", help="Path to wordlist file")
    mode.add_argument("--charset", choices=CHARSETS.keys(),
                      help="Character set for brute-force generation")

    parser.add_argument("--min-len", type=int, default=1,
                        help="Minimum password length for charset mode (default: 1)")
    parser.add_argument("--max-len", type=int, default=6,
                        help="Maximum password length for charset mode (default: 6)")
    parser.add_argument("--threads", type=int, default=8,
                        help="Number of worker threads (default: 8)")
    args = parser.parse_args()

    path = Path(args.archive)
    if not path.exists():
        print(f"[!] File not found: {path}", file=sys.stderr)
        sys.exit(1)

    ext = path.suffix.lower()
    if ext == ".rar":
        if not RAR_AVAILABLE:
            print("[!] rarfile not installed: pip install rarfile", file=sys.stderr)
            sys.exit(1)
        is_rar = True
    elif ext == ".zip":
        is_rar = False
    else:
        # Try ZIP first
        is_rar = False

    print(f"[*] Target: {path}  type={'RAR' if is_rar else 'ZIP'}  threads={args.threads}")

    if args.wordlist:
        wl = Path(args.wordlist)
        if not wl.exists():
            print(f"[!] Wordlist not found: {wl}", file=sys.stderr)
            sys.exit(1)
        print(f"[*] Mode: wordlist ({wl})")
        passwords = wordlist_gen(wl)
    else:
        charset = CHARSETS[args.charset]
        print(f"[*] Mode: charset={args.charset}  len={args.min_len}-{args.max_len}")
        passwords = charset_gen(charset, args.min_len, args.max_len)

    result = launch_workers(path, is_rar, passwords, args.threads)

    if result is not None:
        print(f"[+] Password found: {result!r}")
    else:
        print("[-] Password not found.")


if __name__ == "__main__":
    main()
