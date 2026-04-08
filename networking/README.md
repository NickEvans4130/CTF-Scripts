# Networking

Scripts for network enumeration, service interaction, and traffic analysis.

---

## Scripts

### [port_scanner.py](port_scanner.py)

**Summary:** Scans TCP ports on a target host using TCP connect or raw SYN packets.

**Use cases:**
- Quickly discover open ports on a CTF target machine
- SYN mode is faster and stealthier; connect mode works without root
- Configurable port ranges and multi-threading

**Usage:**
```
python port_scanner.py --host 10.0.0.1 --ports 1-1024
python port_scanner.py --host 10.0.0.1 --ports 22,80,443,8080 --mode connect
python port_scanner.py --host 10.0.0.1 --ports 1-65535 --threads 200 --mode syn
```

**Dependencies:** `socket`, `scapy` (for SYN mode)

---

### [banner_grabber.py](banner_grabber.py)

**Summary:** Connects to open TCP ports and retrieves service banners for version identification.

**Use cases:**
- Identify service versions on open ports found during scanning
- Banner often includes software name and version for vulnerability lookup
- Supports plain TCP, HTTP HEAD, and FTP/SMTP greeting capture

**Usage:**
```
python banner_grabber.py --host 10.0.0.1 --ports 21,22,80,443
python banner_grabber.py --host 10.0.0.1 --port 8080 --http
python banner_grabber.py --targets targets.txt --output banners.txt
```

**Dependencies:** `socket`, `requests`

---

### [dns_zone_transfer.py](dns_zone_transfer.py)

**Summary:** Attempts a DNS zone transfer (AXFR) against all nameservers for a target domain.

**Use cases:**
- Retrieve all DNS records for a domain if zone transfer is misconfigured
- Reveals internal hostnames, IP addresses, and subdomain structure
- Tries all NS records automatically

**Usage:**
```
python dns_zone_transfer.py <domain>
python dns_zone_transfer.py example.com
python dns_zone_transfer.py example.com --nameserver ns1.example.com
```

**Dependencies:** `dnspython`

---

### [arp_spoof_detector.py](arp_spoof_detector.py)

**Summary:** Monitors ARP traffic on the local network to detect ARP spoofing/poisoning attacks.

**Use cases:**
- Detect MitM attacks in a CTF network lab environment
- Alert when a MAC address changes unexpectedly for a known IP
- Log suspicious ARP reply patterns for analysis

**Usage:**
```
python arp_spoof_detector.py --interface eth0
python arp_spoof_detector.py --interface eth0 --output arp_log.txt
python arp_spoof_detector.py --pcap capture.pcap
```

**Dependencies:** `scapy`

---

### [snmp_bruteforcer.py](snmp_bruteforcer.py)

**Summary:** Brute-forces SNMP community strings against a target using a wordlist.

**Use cases:**
- Access SNMP MIB data when the community string is weak (default: `public`, `private`)
- Enumerate system information, running processes, and network interfaces via SNMP
- Supports SNMPv1 and SNMPv2c

**Usage:**
```
python snmp_bruteforcer.py --host 10.0.0.1 --wordlist community_strings.txt
python snmp_bruteforcer.py --host 10.0.0.1 --wordlist strings.txt --version 2c
python snmp_bruteforcer.py --host 10.0.0.1 --community public --dump
```

**Dependencies:** `pysnmp`

---

### [service_bruteforcer.py](service_bruteforcer.py)

**Summary:** Brute-forces login credentials for FTP, SSH, and HTTP Basic Auth services.

**Use cases:**
- Test default or weak credentials on CTF service ports
- Supports username list and password list combinations
- Multi-threaded for parallel attempts; configurable delay to avoid lockouts

**Usage:**
```
python service_bruteforcer.py --service ftp --host 10.0.0.1 --users users.txt --passwords pass.txt
python service_bruteforcer.py --service ssh --host 10.0.0.1 --user root --passwords rockyou.txt
python service_bruteforcer.py --service http-basic --url http://10.0.0.1/admin --users users.txt --passwords pass.txt
```

**Dependencies:** `ftplib`, `paramiko`, `requests`

---

### [netcat_wrapper.py](netcat_wrapper.py)

**Summary:** Python netcat wrapper with auto-reconnect, logging, and scripted interaction support.

**Use cases:**
- Maintain a persistent connection to a CTF service that drops connections
- Log all traffic bidirectionally to a file for review
- Script interaction sequences (send/expect) for automated challenge solving

**Usage:**
```
python netcat_wrapper.py --host 10.0.0.1 --port 1337
python netcat_wrapper.py --host 10.0.0.1 --port 1337 --reconnect --log traffic.txt
python netcat_wrapper.py --host 10.0.0.1 --port 1337 --script interact.py
```

**Dependencies:** `socket`, `threading`

---

### [tls_inspector.py](tls_inspector.py)

**Summary:** Inspects TLS certificates and negotiated cipher suites for a target host.

**Use cases:**
- Extract certificate details (CN, SANs, issuer, validity) from a CTF target
- Identify weak cipher suites or outdated TLS versions
- Check for certificate pinning or self-signed certificates

**Usage:**
```
python tls_inspector.py --host example.com --port 443
python tls_inspector.py --host ctf.example.com --port 8443 --cert-dump
python tls_inspector.py --host example.com --cipher-check
```

**Dependencies:** `ssl`, `cryptography`

---

### [smb_enumerator.py](smb_enumerator.py)

**Summary:** Enumerates SMB shares, users, and sessions on a target host.

**Use cases:**
- List accessible SMB shares on a CTF Windows or Samba target
- Enumerate domain users and groups via RPC
- Check for null session access and guest read permissions

**Usage:**
```
python smb_enumerator.py --host 10.0.0.1
python smb_enumerator.py --host 10.0.0.1 --user guest --password ""
python smb_enumerator.py --host 10.0.0.1 --user admin --password pass --shares --users
```

**Dependencies:** `impacket`, `smbprotocol`

---

### [vpn_proxy_leak_tester.py](vpn_proxy_leak_tester.py)

**Summary:** Tests for VPN and proxy leaks by checking the apparent external IP, DNS resolvers, and WebRTC peers.

**Use cases:**
- Verify a VPN or proxy is not leaking the real IP before performing sensitive OSINT
- Detect DNS leaks where queries bypass the VPN tunnel
- Check WebRTC leak (browser-only via separate tool)

**Usage:**
```
python vpn_proxy_leak_tester.py
python vpn_proxy_leak_tester.py --proxy http://127.0.0.1:8080
python vpn_proxy_leak_tester.py --dns-check --output leak_report.txt
```

**Dependencies:** `requests`, `dnspython`
