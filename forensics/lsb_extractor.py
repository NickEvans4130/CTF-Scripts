#!/usr/bin/env python3
"""
LSB steganography extractor for images and WAV audio files.
"""

import argparse
import sys
import wave
from pathlib import Path

import numpy as np
from PIL import Image


# ── Image extraction ──────────────────────────────────────────────────────────

CHANNEL_MAP = {"R": 0, "G": 1, "B": 2}


def extract_image_lsb(path: Path, channels: list[int], n_bits: int) -> bytes:
    arr = np.array(Image.open(path).convert("RGB"))
    bits = []
    for ch in channels:
        plane = arr[:, :, ch].flatten()
        for pixel in plane:
            for bit in range(n_bits):
                bits.append((int(pixel) >> bit) & 1)

    # Pack bits into bytes (MSB first within each byte)
    out = bytearray()
    for i in range(0, len(bits) - 7, 8):
        byte = 0
        for j in range(8):
            byte |= bits[i + j] << j
        out.append(byte)
    return bytes(out)


# ── Audio extraction ──────────────────────────────────────────────────────────

def extract_wav_lsb(path: Path, channel_idx: int | None, n_bits: int) -> bytes:
    """Extract LSBs from WAV sample data. channel_idx=None means both channels interleaved."""
    with wave.open(str(path), "rb") as wf:
        n_channels = wf.getnchannels()
        sampwidth = wf.getsampwidth()
        n_frames = wf.getnframes()
        raw = wf.readframes(n_frames)

    dtype = {1: np.uint8, 2: np.int16, 4: np.int32}.get(sampwidth)
    if dtype is None:
        print(f"[!] Unsupported sample width: {sampwidth}", file=sys.stderr)
        sys.exit(1)

    samples = np.frombuffer(raw, dtype=dtype)
    # samples are interleaved: [L, R, L, R, ...]
    if channel_idx is not None and n_channels > 1:
        samples = samples[channel_idx::n_channels]

    bits = []
    for s in samples:
        for bit in range(n_bits):
            bits.append((int(s) >> bit) & 1)

    out = bytearray()
    for i in range(0, len(bits) - 7, 8):
        byte = 0
        for j in range(8):
            byte |= bits[i + j] << j
        out.append(byte)
    return bytes(out)


# ── Output helpers ─────────────────────────────────────────────────────────────

def write_output(data: bytes, output: Path | None) -> None:
    printable = all(0x20 <= b < 0x7F or b in (0x09, 0x0A, 0x0D) for b in data[:256])
    if output:
        output.write_bytes(data)
        print(f"[*] {len(data)} bytes written to {output}")
    else:
        if printable:
            print(data[:2000].decode("latin-1"))
        else:
            print(f"[*] First 64 bytes (hex): {data[:64].hex()}")
            print("[!] Output appears binary. Use --output to save to file.")


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Extract LSB-encoded data from images or WAV audio")
    sub = parser.add_subparsers(dest="mode", required=True)

    img_p = sub.add_parser("image", help="Extract from image file")
    img_p.add_argument("file", help="Image file")
    img_p.add_argument("--channel", default="all", choices=["R", "G", "B", "all"],
                       help="Channel(s) to extract from (default: all)")
    img_p.add_argument("--bits", type=int, default=1, choices=range(1, 9),
                       metavar="N", help="Number of LSBs to extract per pixel (default: 1)")
    img_p.add_argument("--output", help="Output file path")

    aud_p = sub.add_parser("audio", help="Extract from WAV file")
    aud_p.add_argument("file", help="WAV audio file")
    aud_p.add_argument("--channel", default="both", choices=["left", "right", "both"],
                       help="Stereo channel (default: both)")
    aud_p.add_argument("--bits", type=int, default=1, choices=range(1, 9),
                       metavar="N", help="Number of LSBs per sample (default: 1)")
    aud_p.add_argument("--output", help="Output file path")

    args = parser.parse_args()
    path = Path(args.file)
    if not path.exists():
        print(f"[!] File not found: {path}", file=sys.stderr)
        sys.exit(1)

    out = Path(args.output) if args.output else None

    if args.mode == "image":
        if args.channel == "all":
            channels = [0, 1, 2]
        else:
            channels = [CHANNEL_MAP[args.channel]]
        print(f"[*] Extracting {args.bits} LSB(s) from {args.channel} channel(s) of {path.name}")
        data = extract_image_lsb(path, channels, args.bits)
    else:
        ch_idx = {"left": 0, "right": 1, "both": None}[args.channel]
        print(f"[*] Extracting {args.bits} LSB(s) from {args.channel} channel of {path.name}")
        data = extract_wav_lsb(path, ch_idx, args.bits)

    write_output(data, out)


if __name__ == "__main__":
    main()
