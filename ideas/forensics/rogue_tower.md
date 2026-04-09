# Script Ideas — Rogue Tower

Scripts that would have accelerated or improved the solution for this challenge.

---

## 1. XOR Key Bruteforcer (data-aware)

**What it would do:**
Given a binary blob and an optional known plaintext prefix (e.g. `picoCTF{`, `FLAG{`, `CTF{`), derive the repeating XOR key automatically. Fall back to full brute-force over common key lengths (1–16 bytes) scoring results by printable ASCII ratio and English-like character distribution.

**Why it would help:**
The manual process here required guessing that the flag started with `picoCTF{` to derive the key `73710709`. A script that tries common CTF flag prefixes against the decoded blob would have found the key in one command.

**Suggested interface:**
```bash
python3 xor_bruteforcer.py --input blob.bin --prefix "picoCTF{" --max-keylen 16
```

---

## 2. PCAP Exfil Extractor

**What it would do:**
Detect exfiltration patterns in a PCAP: repeated small POST requests to the same host, DNS tunneling (long/high-entropy subdomains), ICMP data payloads, or uniform-port sequential streams. For each detected pattern, extract and reassemble the payload, then attempt common decodings (base64, hex, zlib) automatically.

**Why it would help:**
The six sequential POST requests on ports 50000–50005 were a textbook chunked-exfiltration pattern. A dedicated extractor would have surfaced and reassembled the base64 payload immediately, rather than manually iterating TCP streams.

**Suggested interface:**
```bash
python3 pcap_exfil_extractor.py rogue_tower.pcap --output exfil.bin
```

---

## 3. PCAP Anomaly Highlighter

**What it would do:**
Profile all hosts and flows in a PCAP and flag statistical outliers: a device communicating with an IP no other device talks to, broadcast packets with unexpected content, DNS queries with unusually high entropy subdomains, or a device whose traffic volume or destination count deviates significantly from the group.

**Why it would help:**
The rogue tower and the compromised device both stood out statistically — one device talking to a unique IP (`198.51.100.8`), one broadcast from a different source IP with non-carrier content. An anomaly highlighter would have pinpointed both without manual inspection of each packet.

**Suggested interface:**
```bash
python3 pcap_anomaly_highlighter.py rogue_tower.pcap
```

---

## 4. IMSI / Cellular Metadata Parser

**What it would do:**
Parse IMSI strings (from DNS subdomains, User-Agent headers, or raw payloads) and decode their structure: MCC (country), MNC (operator), MSIN (subscriber ID). Cross-reference MCC/MNC against a public database to label carrier and country. Flag devices connecting to a cell ID whose PLMN does not match the IMSI's home network.

**Why it would help:**
The compromised device had IMSI `310410073710709` (AT&T US) but connected to `PLMN=00101` (a test/unauthorized network). An IMSI parser that checks PLMN consistency would have immediately flagged this as a rogue tower attachment.

**Suggested interface:**
```bash
python3 imsi_parser.py --imsi 310410073710709 --connected-plmn 00101
# Output: MCC=310 (US), MNC=410 (AT&T), MSIN=073710709
#         WARNING: connected PLMN 00101 does not match home network 310410
```
