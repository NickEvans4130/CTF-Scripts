#!/usr/bin/env python3
"""
Subdomain enumerator.
Resolves subdomains via DNS and optionally probes HTTP/HTTPS for live hosts.
Supports wordlist-based brute-force and common subdomain prefix lists.
Requires: (no third-party deps for DNS mode; requests for HTTP probing)
"""

import argparse
import concurrent.futures
import socket
import sys

try:
    import requests
    requests.packages.urllib3.disable_warnings()
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

# ── Built-in common subdomain list ───────────────────────────────────────────

COMMON_SUBS = [
    "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "ns2",
    "vpn", "m", "mobile", "api", "dev", "stage", "staging", "test", "demo",
    "portal", "admin", "administrator", "blog", "shop", "store", "app",
    "static", "assets", "media", "cdn", "img", "images", "upload", "uploads",
    "download", "downloads", "files", "secure", "login", "auth", "sso",
    "internal", "intranet", "corp", "support", "help", "forum", "forums",
    "community", "wiki", "docs", "documentation", "status", "monitor",
    "git", "gitlab", "github", "jira", "confluence", "jenkins", "ci",
    "smtp", "imap", "pop3", "mx", "mail2", "email", "webdisk",
    "remote", "access", "vpn2", "extranet", "beta", "alpha", "uat",
    "old", "new", "backup", "bak", "archive", "legacy",
    "api2", "v1", "v2", "v3", "sandbox", "db", "database", "mysql",
    "postgres", "redis", "elastic", "kibana", "grafana", "prometheus",
    "kubernetes", "k8s", "docker", "registry", "proxy", "gateway",
]


def resolve(subdomain: str, domain: str, timeout: float = 3.0) -> list[str]:
    fqdn = f"{subdomain}.{domain}"
    try:
        socket.setdefaulttimeout(timeout)
        results = socket.getaddrinfo(fqdn, None)
        ips = list({r[4][0] for r in results})
        return ips
    except (socket.gaierror, socket.timeout):
        return []


def http_probe(subdomain: str, domain: str, timeout: int) -> dict | None:
    if not HAS_REQUESTS:
        return None
    fqdn = f"{subdomain}.{domain}"
    for scheme in ("https", "http"):
        url = f"{scheme}://{fqdn}/"
        try:
            r = requests.get(url, timeout=timeout, verify=False,
                             allow_redirects=True,
                             headers={"User-Agent": "Mozilla/5.0 (CTF-SubEnum)"})
            return {"url": url, "status": r.status_code,
                    "size": len(r.content),
                    "title": extract_title(r.text)}
        except Exception:
            continue
    return None


def extract_title(html: str) -> str:
    import re
    m = re.search(r"<title[^>]*>(.*?)</title>", html, re.IGNORECASE | re.DOTALL)
    if m:
        return m.group(1).strip()[:80]
    return ""


def worker(args_tuple):
    sub, domain, http, http_timeout, dns_timeout = args_tuple
    ips = resolve(sub, domain, dns_timeout)
    if not ips:
        return None
    result = {"subdomain": sub, "fqdn": f"{sub}.{domain}", "ips": ips, "http": None}
    if http:
        result["http"] = http_probe(sub, domain, http_timeout)
    return result


def load_wordlist(path: str) -> list[str]:
    with open(path) as f:
        return [l.strip() for l in f if l.strip() and not l.startswith("#")]


def main():
    parser = argparse.ArgumentParser(description="Subdomain enumerator via DNS resolution")
    parser.add_argument("--domain",   required=True, help="Target domain (e.g. example.com)")
    parser.add_argument("--wordlist", help="Wordlist file (one subdomain per line)")
    parser.add_argument("--threads",  type=int, default=50)
    parser.add_argument("--http",     action="store_true",
                        help="Probe discovered subdomains over HTTP/HTTPS")
    parser.add_argument("--http-timeout", type=int, default=5, dest="http_timeout")
    parser.add_argument("--dns-timeout",  type=float, default=3.0, dest="dns_timeout")
    parser.add_argument("--output",   help="Save results to file")
    args = parser.parse_args()

    if not HAS_REQUESTS and args.http:
        print("[!] requests not installed — HTTP probing disabled", file=sys.stderr)
        args.http = False

    if args.wordlist:
        wordlist = load_wordlist(args.wordlist)
    else:
        wordlist = COMMON_SUBS

    print(f"[*] Domain:  {args.domain}")
    print(f"[*] Words:   {len(wordlist)}")
    print(f"[*] Threads: {args.threads}")
    print(f"[*] HTTP probe: {args.http}\n")

    tasks = [(s, args.domain, args.http, args.http_timeout, args.dns_timeout)
             for s in wordlist]

    found = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as ex:
        for i, result in enumerate(ex.map(worker, tasks), 1):
            if result:
                fqdn = result["fqdn"]
                ips  = ", ".join(result["ips"])
                http = result["http"]
                if http:
                    title = http.get("title", "")
                    print(f"  [+] {fqdn:<50} {ips}  HTTP {http['status']}  {http['size']}B  {title!r}")
                else:
                    print(f"  [+] {fqdn:<50} {ips}")
                found.append(result)
            if i % 200 == 0:
                print(f"  [*] {i}/{len(tasks)} checked ...", flush=True)

    print(f"\n[*] {len(found)} subdomain(s) found")

    if args.output and found:
        with open(args.output, "w") as f:
            for r in found:
                http_url = r["http"]["url"] if r["http"] else ""
                f.write(f"{r['fqdn']}\t{','.join(r['ips'])}\t{http_url}\n")
        print(f"[*] Results saved to {args.output}")


if __name__ == "__main__":
    main()
