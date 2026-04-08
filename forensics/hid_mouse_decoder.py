#!/usr/bin/env python3
"""
USB HID mouse movement decoder.
Reads relative X/Y from mouse HID reports in a PCAP and reconstructs the cursor path.
Requires: scapy, matplotlib
"""

import argparse
import ctypes
import sys
from pathlib import Path

try:
    from scapy.all import rdpcap
except ImportError:
    print("[!] scapy not installed: pip install scapy", file=sys.stderr)
    sys.exit(1)

try:
    import matplotlib.pyplot as plt
except ImportError:
    print("[!] matplotlib not installed: pip install matplotlib", file=sys.stderr)
    sys.exit(1)


def signed_byte(val: int) -> int:
    """Interpret an unsigned byte as a signed int8."""
    return ctypes.c_int8(val).value


def extract_mouse_events(packets) -> list[tuple[int, int]]:
    """
    Extract (dx, dy) pairs from USB HID mouse reports.
    Standard boot-protocol mouse report: byte0=buttons, byte1=dx, byte2=dy
    Some reports have a 4-byte format: byte0=buttons, byte1=dx, byte2=dy, byte3=wheel
    """
    events = []
    for pkt in packets:
        raw = bytes(pkt)
        # USB HID data in Wireshark is usually in the leftover capture data (last N bytes).
        # The USB bulk transfer payload is typically in the last 4 or 8 bytes of the frame.
        # We look for USB URB data by checking known offsets.
        # For usbmon captures, HID data typically starts at offset 27 or 40.
        for offset in (27, 40, 64):
            if len(raw) >= offset + 3:
                buttons = raw[offset]
                dx = signed_byte(raw[offset + 1])
                dy = signed_byte(raw[offset + 2])
                # Filter out empty reports and non-mouse garbage
                if dx != 0 or dy != 0:
                    events.append((dx, dy))
                    break
    return events


def reconstruct_path(events: list[tuple[int, int]]) -> tuple[list[int], list[int]]:
    x, y = 0, 0
    xs, ys = [0], [0]
    for dx, dy in events:
        x += dx
        y += dy
        xs.append(x)
        ys.append(y)
    return xs, ys


def plot_path(xs: list[int], ys: list[int], output: Path | None, scale: float) -> None:
    fig, ax = plt.subplots(figsize=(12 * scale, 8 * scale))
    ax.plot(xs, ys, color="black", linewidth=0.8)
    ax.set_aspect("equal")
    # Invert Y to match screen coordinates (Y increases downward)
    ax.invert_yaxis()
    ax.set_title("USB HID Mouse Path")
    ax.axis("off")
    if output:
        fig.savefig(output, dpi=150, bbox_inches="tight")
        print(f"[*] Path image saved to {output}")
    else:
        plt.show()


def main():
    parser = argparse.ArgumentParser(description="Decode USB HID mouse movements from a PCAP")
    parser.add_argument("file", help="PCAP file containing USB HID mouse traffic")
    parser.add_argument("--output", help="Save path image to file (PNG/PDF)")
    parser.add_argument("--scale", type=float, default=1.0,
                        help="Figure scale multiplier (default: 1.0)")
    args = parser.parse_args()

    path = Path(args.file)
    if not path.exists():
        print(f"[!] File not found: {path}", file=sys.stderr)
        sys.exit(1)

    print(f"[*] Loading {path} ...")
    packets = rdpcap(str(path))
    print(f"[*] {len(packets)} packets loaded")

    events = extract_mouse_events(packets)
    print(f"[*] {len(events)} movement event(s) extracted")

    if not events:
        print("[!] No mouse events found. Check that this PCAP contains USB HID mouse traffic.")
        sys.exit(1)

    xs, ys = reconstruct_path(events)
    x_range = max(xs) - min(xs)
    y_range = max(ys) - min(ys)
    print(f"[*] Path bounding box: {x_range} x {y_range} units")

    out = Path(args.output) if args.output else None
    plot_path(xs, ys, out, args.scale)


if __name__ == "__main__":
    main()
