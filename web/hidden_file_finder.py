#!/usr/bin/env python3
"""
Hidden file and directory finder.
Probes for common sensitive files, backup artefacts, config leaks,
version control exposure, and admin panels.
Requires: requests
"""

import argparse
import concurrent.futures
import sys

try:
    import requests
    requests.packages.urllib3.disable_warnings()
except ImportError:
    print("[!] requests not installed: pip install requests", file=sys.stderr)
    sys.exit(1)

# ── Target path lists ─────────────────────────────────────────────────────────

SENSITIVE_FILES = [
    # VCS
    "/.git/HEAD", "/.git/config", "/.git/COMMIT_EDITMSG", "/.svn/entries",
    "/.hg/hgrc", "/.bzr/README",
    # Config / credentials
    "/.env", "/.env.local", "/.env.backup", "/.env.bak", "/.env.example",
    "/config.php", "/config.yml", "/config.yaml", "/config.json",
    "/settings.py", "/settings.cfg", "/application.properties",
    "/database.yml", "/secrets.yml", "/credentials.json",
    "/wp-config.php", "/wp-config.php.bak", "/LocalSettings.php",
    # Backups
    "/backup.zip", "/backup.tar.gz", "/backup.sql", "/dump.sql",
    "/db.sql", "/database.sql", "/site.zip", "/www.zip",
    "/index.php.bak", "/index.html.bak", "/config.php.bak",
    # Debug / info
    "/phpinfo.php", "/info.php", "/test.php", "/debug.php",
    "/server-status", "/server-info", "/.htaccess", "/.htpasswd",
    # Admin panels
    "/admin", "/admin/", "/administrator", "/wp-admin", "/wp-login.php",
    "/login", "/login.php", "/panel", "/dashboard", "/manager",
    "/console", "/phpmyadmin", "/adminer.php", "/adminer",
    # Logs
    "/logs/", "/log/", "/error.log", "/access.log", "/debug.log",
    "/application.log", "/app.log",
    # Package manager / CI
    "/package.json", "/package-lock.json", "/yarn.lock", "/composer.json",
    "/Gemfile", "/Gemfile.lock", "/requirements.txt", "/Pipfile",
    "/.travis.yml", "/.github/workflows/", "/Dockerfile",
    "/docker-compose.yml", "/Makefile",
    # Swagger / API docs
    "/swagger.json", "/swagger.yaml", "/openapi.json", "/openapi.yaml",
    "/api-docs", "/api/docs", "/api/swagger",
    # Source maps
    "/static/js/main.js.map", "/bundle.js.map",
    # robots / sitemap
    "/robots.txt", "/sitemap.xml", "/crossdomain.xml", "/clientaccesspolicy.xml",
    # Misc
    "/.DS_Store", "/Thumbs.db", "/web.config", "/WEB-INF/web.xml",
    "/.well-known/security.txt", "/.well-known/acme-challenge/",
    "/CHANGELOG", "/CHANGELOG.md", "/CHANGELOG.txt",
    "/README", "/README.md", "/README.txt",
    "/INSTALL", "/INSTALL.md", "/TODO",
]

INTERESTING_CONTENT = [
    "password", "secret", "api_key", "api key", "access_token", "private_key",
    "BEGIN RSA", "BEGIN EC PRIVATE", "BEGIN OPENSSH",
    "root:", "admin:", "flag{", "ctf{", "htb{", "token",
    "database_url", "db_pass", "db_password",
]


def make_session(headers: list[str]) -> requests.Session:
    s = requests.Session()
    s.headers["User-Agent"] = "Mozilla/5.0 (CTF-HiddenFiles)"
    for h in headers:
        k, _, v = h.partition(":")
        s.headers[k.strip()] = v.strip()
    return s


def probe_path(session, base_url: str, path: str, timeout: int) -> dict | None:
    url = base_url.rstrip("/") + path
    try:
        r = session.get(url, timeout=timeout, verify=False, allow_redirects=False)
        if r.status_code in (200, 206):
            content_hits = [s for s in INTERESTING_CONTENT
                            if s.lower() in r.text.lower()]
            return {
                "path": path, "url": url, "status": r.status_code,
                "size": len(r.content), "hits": content_hits,
                "snippet": r.text[:200].replace('\n', ' '),
                "ct": r.headers.get("Content-Type", ""),
            }
        elif r.status_code in (301, 302, 403):
            return {
                "path": path, "url": url, "status": r.status_code,
                "size": len(r.content), "hits": [],
                "snippet": "", "ct": "",
            }
    except Exception:
        pass
    return None


def worker(args_tuple):
    session, base_url, path, timeout = args_tuple
    return probe_path(session, base_url, path, timeout)


def main():
    parser = argparse.ArgumentParser(description="Hidden file and sensitive path finder")
    parser.add_argument("--url",     required=True, help="Target base URL (e.g. https://target.com)")
    parser.add_argument("--wordlist", help="Extra paths to test (one per line, in addition to built-in)")
    parser.add_argument("--threads", type=int, default=20)
    parser.add_argument("--timeout", type=int, default=8)
    parser.add_argument("--headers", action="append", default=[], metavar="H:V")
    parser.add_argument("--200-only", action="store_true", dest="ok_only",
                        help="Only report HTTP 200 responses")
    args = parser.parse_args()

    session = make_session(args.headers)

    paths = list(SENSITIVE_FILES)
    if args.wordlist:
        with open(args.wordlist) as f:
            extra = [l.strip() for l in f if l.strip() and not l.startswith("#")]
            paths += [p if p.startswith("/") else "/" + p for p in extra]

    print(f"[*] Target:  {args.url}")
    print(f"[*] Paths:   {len(paths)}")
    print(f"[*] Threads: {args.threads}\n")

    tasks   = [(session, args.url, p, args.timeout) for p in paths]
    found   = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as ex:
        for i, result in enumerate(ex.map(worker, tasks), 1):
            if result is None:
                pass
            elif result["status"] == 200:
                hits = result["hits"]
                marker = "[+]" if hits else "[~]"
                print(f"  {marker} {result['status']}  {result['path']:<55} "
                      f"{result['size']}B  {result['ct'][:30]}")
                if hits:
                    print(f"      Sensitive content: {hits}")
                    print(f"      Snippet: {result['snippet'][:120]}")
                found.append(result)
            elif not args.ok_only and result["status"] in (301, 302, 403):
                print(f"  [-] {result['status']}  {result['path']}")
            if i % 50 == 0:
                print(f"\r  [*] {i}/{len(tasks)} checked ...", end="", flush=True)

    print(f"\n[*] {len(found)} accessible path(s) found")
    crit = [r for r in found if r["hits"]]
    if crit:
        print(f"[+] {len(crit)} path(s) with sensitive content indicators:")
        for r in crit:
            print(f"    {r['url']}  -> {r['hits']}")


if __name__ == "__main__":
    main()
