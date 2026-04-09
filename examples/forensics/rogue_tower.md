# Rogue Tower (PCAP Forensics)

**Challenge:** Analyze captured network traffic to identify a rogue cell tower, find the compromised device, and recover the exfiltrated flag.

**File:** `rogue_tower.pcap`

**Flag:** `picoCTF{r0gu3_c3ll_t0w3r_aab7ef8d}`

---

## Scripts Used

### `forensics/pcap_analyser.py`

The primary tool for this challenge. Run in all three modes:

```bash
python3 forensics/pcap_analyser.py rogue_tower.pcap --mode dns
python3 forensics/pcap_analyser.py rogue_tower.pcap --mode tcp
```

**DNS mode** revealed devices registering with a carrier via subdomains encoding their IMSI:
```
device-310410073710709.network.com
device-310410287906306.network.com
...
```

**TCP mode** identified the compromised device (`10.100.97.10`) making POST requests to a suspicious IP (`198.51.100.8`) on ports 50000–50005, uploading chunked base64 payloads — clearly exfiltrating data.

---

## Analysis Steps

### 1. Identify the rogue tower

Two broadcast UDP packets (to 255.255.255.255:55000) advertised legitimate towers:
```
CARRIER: Verizon PLMN=310410 CELLID=25290
CARRIER: AT&T   PLMN=310410 CELLID=25291
```

A third broadcast revealed the rogue tower:
```
UNAUTHORIZED-TEST-NETWORK PLMN=00101 CELLID=97605
```

**Rogue tower IP:** `192.168.99.1`

### 2. Find the compromised device

Packet 15 (HTTP GET from `10.100.97.10` to the rogue IP `198.51.100.8`):
```
User-Agent: MobileDevice/1.0 (IMSI:310410073710709; CELL:97605)
```

The device registered with `CELL:97605` — the rogue tower's cell ID, confirming it was tricked into connecting.

**Compromised device:** `10.100.97.10`, IMSI `310410073710709`

### 3. Recover the flag

Six POST requests to `198.51.100.8:443/upload` uploaded chunked base64:
```
R1pUXnNjd  kJFA1BEA2  hTCltfaEU  AQANLaFJW  UwdSVgFTT  g==
```

Concatenated and base64-decoded, the payload was XOR-obfuscated binary. The XOR key was `73710709` — the last 8 digits of the compromised device's IMSI (MSIN portion of `310410073710709`).

```python
import base64
decoded = base64.b64decode('R1pUXnNjdkJFA1BEA2hTCltfaEUAQANLaFJWUwdSVgFTTg==')
key = b'73710709'
flag = bytes(decoded[i] ^ key[i % len(key)] for i in range(len(decoded)))
# picoCTF{r0gu3_c3ll_t0w3r_aab7ef8d}
```

---

## Key Takeaways

- `pcap_analyser.py --mode dns` is invaluable for finding hostname-encoded metadata (IMSIs, device IDs).
- `pcap_analyser.py --mode tcp` quickly surfaces suspicious one-sided exfiltration streams and their raw payloads.
- When exfiltrated data is obfuscated, look for XOR keys derived from artifacts already present in the capture (IMSIs, cell IDs, PLMNs).
