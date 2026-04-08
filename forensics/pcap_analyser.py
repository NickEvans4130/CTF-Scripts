#!/usr/bin/env python3
"""
PCAP analyser - extract HTTP requests/responses, DNS queries, and TCP streams.
Requires: scapy
"""

import argparse
import collections
import sys
from pathlib import Path

try:
    from scapy.all import rdpcap, TCP, UDP, IP, Raw
    from scapy.layers.dns import DNS, DNSQR, DNSRR
    from scapy.layers.http import HTTP, HTTPRequest, HTTPResponse
except ImportError:
    print("[!] scapy not installed: pip install scapy", file=sys.stderr)
    sys.exit(1)


# ── HTTP ──────────────────────────────────────────────────────────────────────

def extract_http(packets) -> None:
    print("[*] HTTP Requests/Responses\n" + "=" * 60)
    for pkt in packets:
        if pkt.haslayer(HTTPRequest):
            req = pkt[HTTPRequest]
            host = req.Host.decode() if req.Host else "?"
            method = req.Method.decode() if req.Method else "?"
            path = req.Path.decode() if req.Path else "/"
            print(f"  REQ  {method} http://{host}{path}")
            if req.haslayer(Raw):
                body = req[Raw].load
                if body:
                    print(f"       Body: {body[:200]}")
        elif pkt.haslayer(HTTPResponse):
            resp = pkt[HTTPResponse]
            status = resp.Status_Code.decode() if resp.Status_Code else "?"
            print(f"  RESP {status}")
            if resp.haslayer(Raw):
                body = resp[Raw].load
                if body:
                    print(f"       Body (first 200): {body[:200]}")


# ── DNS ───────────────────────────────────────────────────────────────────────

def extract_dns(packets, output: Path | None) -> None:
    print("[*] DNS Queries\n" + "=" * 60)
    queries = []
    for pkt in packets:
        if pkt.haslayer(DNS):
            dns = pkt[DNS]
            if dns.qr == 0 and dns.qdcount > 0:  # query
                name = dns[DNSQR].qname.decode().rstrip(".")
                qtype = dns[DNSQR].qtype
                queries.append((name, qtype))
                print(f"  Q  {name}  (type={qtype})")
            elif dns.qr == 1 and dns.ancount > 0:  # response
                an = dns[DNSRR]
                while an:
                    rdata = an.rdata if hasattr(an, "rdata") else "?"
                    print(f"  A  {an.rrname.decode().rstrip('.')}  -> {rdata}")
                    an = an.payload if an.payload and an.payload.name != "NoPayload" else None

    if output and queries:
        with open(output, "w") as fh:
            for name, qtype in queries:
                fh.write(f"{name}\t{qtype}\n")
        print(f"\n[*] DNS queries written to {output}")


# ── TCP streams ───────────────────────────────────────────────────────────────

def extract_tcp_streams(packets, stream_id: int | None) -> None:
    # Group packets by 4-tuple
    streams: dict = collections.defaultdict(list)
    for pkt in packets:
        if pkt.haslayer(TCP) and pkt.haslayer(IP):
            key = tuple(sorted([
                (pkt[IP].src, pkt[TCP].sport),
                (pkt[IP].dst, pkt[TCP].dport),
            ]))
            streams[key].append(pkt)

    stream_list = list(streams.items())
    print(f"[*] {len(stream_list)} TCP stream(s) found")

    if stream_id is not None:
        if stream_id >= len(stream_list):
            print(f"[!] Stream {stream_id} does not exist (max: {len(stream_list)-1})")
            return
        stream_list = [stream_list[stream_id]]

    for i, (key, pkts) in enumerate(stream_list):
        (src, sport), (dst, dport) = key
        payload = b"".join(
            bytes(p[Raw].load) for p in pkts if p.haslayer(Raw)
        )
        print(f"\n  Stream {i}: {src}:{sport} <-> {dst}:{dport}  ({len(payload)} payload bytes)")
        if payload:
            try:
                print(payload[:500].decode("utf-8", errors="replace"))
            except Exception:
                print(payload[:500].hex())


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Analyse PCAP files: HTTP, DNS, TCP streams")
    parser.add_argument("file", help="PCAP or PCAPNG file")
    parser.add_argument("--mode", choices=["http", "dns", "tcp", "all"], default="all",
                        help="Analysis mode (default: all)")
    parser.add_argument("--stream", type=int, default=None,
                        help="TCP stream index to dump (for --mode tcp)")
    parser.add_argument("--output", help="Write extracted data to file")
    args = parser.parse_args()

    path = Path(args.file)
    if not path.exists():
        print(f"[!] File not found: {path}", file=sys.stderr)
        sys.exit(1)

    print(f"[*] Loading {path} ...")
    packets = rdpcap(str(path))
    print(f"[*] {len(packets)} packets loaded\n")

    out = Path(args.output) if args.output else None

    if args.mode in ("http", "all"):
        extract_http(packets)
        print()
    if args.mode in ("dns", "all"):
        extract_dns(packets, out if args.mode == "dns" else None)
        print()
    if args.mode in ("tcp", "all"):
        extract_tcp_streams(packets, args.stream)


if __name__ == "__main__":
    main()
