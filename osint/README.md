# OSINT

Scripts for open-source intelligence gathering and data aggregation.

---

## Scripts

### [username_lookup.py](username_lookup.py)

**Summary:** Checks a username across multiple social media and online platforms simultaneously.

**Use cases:**
- Track down a CTF persona's accounts across GitHub, Twitter, Reddit, HackerNews, etc.
- Multi-threaded concurrent checks for speed
- Returns live URLs for confirmed accounts

**Usage:**
```
python username_lookup.py <username>
python username_lookup.py john_doe
python username_lookup.py john_doe --platforms github,twitter,reddit --output found.txt
```

**Dependencies:** `requests`, `threading`

---

### [reverse_image_search.py](reverse_image_search.py)

**Summary:** Generates direct reverse image search URLs for Google, Bing, TinEye, and Yandex from a local file or URL.

**Use cases:**
- Identify the origin of an image provided in a CTF challenge
- Find higher-resolution versions or pages that embed the image
- Batch generate search links for multiple images

**Usage:**
```
python reverse_image_search.py <image_file_or_url>
python reverse_image_search.py image.jpg
python reverse_image_search.py https://example.com/photo.jpg --open-browser
```

**Dependencies:** `webbrowser`, `requests` (for URL upload)

---

### [whois_dns_query.py](whois_dns_query.py)

**Summary:** Performs WHOIS lookups and queries all common DNS record types for a batch of domains.

**Use cases:**
- Gather registrant info, nameservers, and registration dates from WHOIS
- Enumerate A, AAAA, MX, TXT, NS, SOA, CNAME, SRV records
- Batch mode processes a list of domains from a file

**Usage:**
```
python whois_dns_query.py <domain>
python whois_dns_query.py example.com
python whois_dns_query.py --file domains.txt --output results.json
python whois_dns_query.py example.com --types A,MX,TXT
```

**Dependencies:** `python-whois`, `dnspython`

---

### [cert_transparency_search.py](cert_transparency_search.py)

**Summary:** Searches certificate transparency logs (crt.sh) for subdomains and certificates issued for a domain.

**Use cases:**
- Discover subdomains that are not exposed in DNS but have valid TLS certificates
- Find wildcard certs that hint at infrastructure patterns
- Historical certificate records may reveal decommissioned or staging hosts

**Usage:**
```
python cert_transparency_search.py <domain>
python cert_transparency_search.py example.com
python cert_transparency_search.py example.com --unique-subdomains --output subs.txt
```

**Dependencies:** `requests`

---

### [wayback_fetcher.py](wayback_fetcher.py)

**Summary:** Fetches archived URLs and page snapshots for a domain from the Wayback Machine API.

**Use cases:**
- Retrieve a deleted page that contained a flag or credential
- List all archived URLs for a domain to find hidden endpoints
- Download a specific snapshot by timestamp

**Usage:**
```
python wayback_fetcher.py <url>
python wayback_fetcher.py http://example.com/secret-page
python wayback_fetcher.py http://example.com --list-urls --output urls.txt
python wayback_fetcher.py http://example.com/page --timestamp 20230101120000
```

**Dependencies:** `requests`

---

### [shodan_formatter.py](shodan_formatter.py)

**Summary:** Formats and generates Shodan search queries for common CTF-relevant search patterns.

**Use cases:**
- Build Shodan dorks for finding exposed services, specific banners, or default credentials
- Construct queries for `org:`, `hostname:`, `port:`, `product:`, `vuln:` filters
- Output formatted query strings ready to paste into Shodan

**Usage:**
```
python shodan_formatter.py --org "Target Org" --port 8080
python shodan_formatter.py --product "nginx" --country US --vuln CVE-2021-41773
python shodan_formatter.py --hostname ctf.example.com
```

**Dependencies:** `shodan` (optional, for direct API queries)

---

### [email_header_parser.py](email_header_parser.py)

**Summary:** Parses email headers to trace the delivery path, extract IP addresses, and geolocate sender hops.

**Use cases:**
- Trace the true sending IP of a phishing or challenge email through Received headers
- Geolocate each hop in the mail relay chain
- Identify spoofed From addresses via SPF/DKIM/DMARC header inspection

**Usage:**
```
python email_header_parser.py <eml_file>
python email_header_parser.py email.eml
python email_header_parser.py email.eml --geolocate --output trace.json
```

**Dependencies:** `email`, `requests` (for IP geolocation API)

---

### [phone_osint.py](phone_osint.py)

**Summary:** Aggregates OSINT data for a phone number: carrier, region, line type, and public record lookups.

**Use cases:**
- Identify the carrier and country of origin of a phone number in a challenge
- Check whether a number appears in public breach databases
- Format normalisation for international numbers

**Usage:**
```
python phone_osint.py <phone_number>
python phone_osint.py +14155552671
python phone_osint.py +14155552671 --output result.json
```

**Dependencies:** `phonenumbers`, `requests`

---

### [github_dorking.py](github_dorking.py)

**Summary:** Builds and optionally executes GitHub code search queries (dorks) to find leaked secrets and sensitive files.

**Use cases:**
- Search for hardcoded API keys, passwords, or flag strings in a target's repos
- Find `.env`, `config.json`, or private key files accidentally committed
- Target a specific organisation or user's repositories

**Usage:**
```
python github_dorking.py --query "password" --org target-org
python github_dorking.py --query "CTF{" --user targetuser --lang python
python github_dorking.py --dork-file dorks.txt --org target-org --token $GITHUB_TOKEN
```

**Dependencies:** `requests`, `PyGithub`

---

### [pastebin_leak_scanner.py](pastebin_leak_scanner.py)

**Summary:** Searches Pastebin and GitHub Gists for pastes containing a target keyword, domain, or flag format.

**Use cases:**
- Find CTF flags or credentials that have been pasted publicly
- Monitor for leaks matching a specific domain or email address
- Archive matching paste content before it is deleted

**Usage:**
```
python pastebin_leak_scanner.py --keyword "ctf.example.com"
python pastebin_leak_scanner.py --keyword "flag{" --output pastes/
python pastebin_leak_scanner.py --keyword "example@email.com" --sources pastebin,gist
```

**Dependencies:** `requests`
