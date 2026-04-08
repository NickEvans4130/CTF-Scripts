# Web

Scripts for web application attack techniques common in CTF challenges.

---

## Scripts

### [dir_bruteforcer.py](dir_bruteforcer.py)

**Summary:** Brute-forces directories and files on a web server using a wordlist.

**Use cases:**
- Discover hidden admin panels, flag files, or backup directories
- Supports extensions (`.php`, `.txt`, `.bak`) appended to each wordlist entry
- Multi-threaded for speed; configurable status code filtering

**Usage:**
```
python dir_bruteforcer.py --url http://target/ --wordlist common.txt
python dir_bruteforcer.py --url http://target/ --wordlist dirs.txt --ext php,txt,bak
python dir_bruteforcer.py --url http://target/ --wordlist big.txt --threads 20 --status 200,403
```

**Dependencies:** `requests`, `threading`

---

### [sqli_fuzzer.py](sqli_fuzzer.py)

**Summary:** Fuzzes URL parameters and POST fields with SQL injection payloads to detect injection points.

**Use cases:**
- Detect error-based, boolean-based, and time-based SQLi in CTF web challenges
- Payload library covers MySQL, PostgreSQL, SQLite, and MSSQL variants
- Reports which payloads triggered different responses

**Usage:**
```
python sqli_fuzzer.py --url "http://target/page?id=1" --param id
python sqli_fuzzer.py --url http://target/login --method POST --data "user=admin&pass=test" --param user
python sqli_fuzzer.py --url "http://target/?id=1" --param id --mode time
```

**Dependencies:** `requests`

---

### [ssrf_probe.py](ssrf_probe.py)

**Summary:** Probes a target parameter for SSRF by injecting common internal endpoint URLs and cloud metadata addresses.

**Use cases:**
- Test for SSRF to reach AWS/GCP metadata APIs (`169.254.169.254`)
- Probe internal services (`localhost`, `127.0.0.1`, `10.x.x.x`) via a vulnerable parameter
- Supports out-of-band detection via collaborator URLs

**Usage:**
```
python ssrf_probe.py --url "http://target/fetch?url=" --param url
python ssrf_probe.py --url "http://target/fetch?url=" --targets ssrf_targets.txt
python ssrf_probe.py --url "http://target/fetch?url=" --oob-host your.burp.collaborator
```

**Dependencies:** `requests`

---

### [lfi_fuzzer.py](lfi_fuzzer.py)

**Summary:** Fuzzes a parameter with LFI/path traversal payloads to read arbitrary files.

**Use cases:**
- Detect LFI to read `/etc/passwd`, `/flag`, or application source files
- Payload list includes `../` chains, null bytes, URL/double encoding, and filter bypasses
- Reports which payloads returned distinguishable file content

**Usage:**
```
python lfi_fuzzer.py --url "http://target/page?file=index" --param file
python lfi_fuzzer.py --url "http://target/page?file=index" --param file --target /flag
python lfi_fuzzer.py --url "http://target/" --param file --encode url
```

**Dependencies:** `requests`

---

### [param_pollution_tester.py](param_pollution_tester.py)

**Summary:** Tests HTTP parameter pollution by sending duplicate parameters with different values.

**Use cases:**
- Bypass input validation by sending `user=admin&user=attacker`
- Test how the server (and any WAF in front) resolves duplicate parameters
- Covers both GET and POST, and various serialisation formats

**Usage:**
```
python param_pollution_tester.py --url http://target/page --param role --values user,admin
python param_pollution_tester.py --url http://target/page --param role --values user,admin --method POST
```

**Dependencies:** `requests`

---

### [cookie_jwt_tamperer.py](cookie_jwt_tamperer.py)

**Summary:** Decodes, modifies, and re-encodes cookies and JWT tokens.

**Use cases:**
- Decode a JWT to inspect claims without a library
- Modify a cookie value (base64, JSON, Flask session) and re-encode
- Brute-force weak JWT secrets or apply the none-algorithm bypass

**Usage:**
```
python cookie_jwt_tamperer.py --jwt <token> --decode
python cookie_jwt_tamperer.py --jwt <token> --set-claim admin=true --secret newsecret
python cookie_jwt_tamperer.py --cookie <value> --decode --type flask
```

**Dependencies:** `PyJWT`, `itsdangerous`, `base64`

---

### [http_header_injector.py](http_header_injector.py)

**Summary:** Sends requests with injected or spoofed HTTP headers to test trust-based bypasses.

**Use cases:**
- Inject `X-Forwarded-For`, `X-Real-IP` to spoof IP-based access controls
- Test `Host` header injection for SSRF or password reset link manipulation
- Inject arbitrary headers to probe backend parsing behaviour

**Usage:**
```
python http_header_injector.py --url http://target/ --header "X-Forwarded-For: 127.0.0.1"
python http_header_injector.py --url http://target/ --header "Host: internal.target.com"
python http_header_injector.py --url http://target/ --headers-file headers.txt
```

**Dependencies:** `requests`

---

### [ssti_tester.py](ssti_tester.py)

**Summary:** Tests parameters for Server-Side Template Injection using payloads for Jinja2, Twig, and Freemarker.

**Use cases:**
- Detect SSTI in web challenge input fields or URL parameters
- Escalate to RCE using engine-specific payload chains
- Identifies the template engine from error messages or response differences

**Usage:**
```
python ssti_tester.py --url "http://target/page?name=test" --param name
python ssti_tester.py --url http://target/ --param name --method POST --data "name=test"
python ssti_tester.py --url "http://target/?name=test" --param name --engine jinja2 --rce
```

**Dependencies:** `requests`

---

### [xxe_injector.py](xxe_injector.py)

**Summary:** Injects XXE payloads into XML input fields to read files or trigger SSRF.

**Use cases:**
- Read `/etc/passwd` or `/flag` via classic XXE file read
- Exploit blind XXE via out-of-band DNS/HTTP exfiltration
- Test SOAP endpoints, XML upload features, and SVG parsers

**Usage:**
```
python xxe_injector.py --url http://target/upload --file payload.xml
python xxe_injector.py --url http://target/api --mode file-read --target /etc/passwd
python xxe_injector.py --url http://target/api --mode oob --oob-host your.server.com
```

**Dependencies:** `requests`

---

### [cors_tester.py](cors_tester.py)

**Summary:** Tests a target URL for CORS misconfigurations by sending requests with various Origin headers.

**Use cases:**
- Detect `Access-Control-Allow-Origin: *` or origin reflection vulnerabilities
- Check whether credentials are allowed with a wildcard or reflected origin
- Identify pre-flight handling issues

**Usage:**
```
python cors_tester.py --url http://target/api/data
python cors_tester.py --url http://target/api/data --origin https://evil.com
python cors_tester.py --url http://target/api/data --with-credentials
```

**Dependencies:** `requests`

---

### [open_redirect_fuzzer.py](open_redirect_fuzzer.py)

**Summary:** Fuzzes redirect parameters with payloads to detect open redirect vulnerabilities.

**Use cases:**
- Detect open redirects in `?next=`, `?redirect=`, `?url=` parameters
- Payload list includes absolute URLs, protocol-relative, and bypass variants
- Reports which payloads result in a redirect to an external host

**Usage:**
```
python open_redirect_fuzzer.py --url "http://target/login?next=/" --param next
python open_redirect_fuzzer.py --url "http://target/login?next=/" --param next --target https://evil.com
```

**Dependencies:** `requests`

---

### [subdomain_enumerator.py](subdomain_enumerator.py)

**Summary:** Enumerates subdomains of a target domain using a wordlist and DNS resolution.

**Use cases:**
- Discover hidden subdomains hosting challenge infrastructure
- Multi-threaded DNS resolution for speed
- Optional HTTP probing to find live web services

**Usage:**
```
python subdomain_enumerator.py --domain target.com --wordlist subdomains.txt
python subdomain_enumerator.py --domain target.com --wordlist subdomains.txt --threads 50 --http-probe
```

**Dependencies:** `dnspython`, `requests`, `threading`

---

### [hidden_file_finder.py](hidden_file_finder.py)

**Summary:** Probes a web server for common sensitive paths: `robots.txt`, `sitemap.xml`, `.git`, `.env`, and backup files.

**Use cases:**
- Quickly check a CTF web target for low-hanging fruit before deeper enumeration
- `.git` folder exposure allows source code reconstruction
- Backup files (`.bak`, `.old`, `~`) may expose source code with credentials

**Usage:**
```
python hidden_file_finder.py --url http://target/
python hidden_file_finder.py --url http://target/ --output found.txt
```

**Dependencies:** `requests`

---

### [graphql_introspection.py](graphql_introspection.py)

**Summary:** Runs a GraphQL introspection query and formats the schema, types, and available queries/mutations.

**Use cases:**
- Enumerate all GraphQL types and fields on a challenge endpoint
- Find sensitive queries or mutations not shown in documentation
- Dump full schema to plan further attacks

**Usage:**
```
python graphql_introspection.py --url http://target/graphql
python graphql_introspection.py --url http://target/graphql --headers "Authorization: Bearer token"
```

**Dependencies:** `requests`

---

### [websocket_fuzzer.py](websocket_fuzzer.py)

**Summary:** Connects to a WebSocket endpoint and fuzzes messages with a payload list.

**Use cases:**
- Test WebSocket-based CTF challenges for injection or logic vulnerabilities
- Replay and modify captured WebSocket messages
- Supports authentication headers and subprotocols

**Usage:**
```
python websocket_fuzzer.py --url ws://target/ws --payloads payloads.txt
python websocket_fuzzer.py --url ws://target/ws --message '{"action":"getflag"}' --fuzz-field action
```

**Dependencies:** `websockets`

---

### [request_replay_proxy.py](request_replay_proxy.py)

**Summary:** Captures, replays, and modifies HTTP requests acting as a lightweight local proxy.

**Use cases:**
- Replay a saved request with modified headers, cookies, or body
- Script multi-step HTTP sequences (login then access flag endpoint)
- Lightweight alternative to Burp Repeater for scripted attacks

**Usage:**
```
python request_replay_proxy.py --request request.txt --modify "Cookie: session=newvalue"
python request_replay_proxy.py --url http://target/ --method POST --data "user=admin&pass=test"
```

**Dependencies:** `requests`
