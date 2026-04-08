#!/usr/bin/env python3
"""
WAV/MP3 LSB extractor.
WAV: extracts LSBs from PCM sample data.
MP3: dumps ID3 tags and checks ancillary data bytes in MPEG frames.
Requires: numpy (WAV), mutagen (MP3 tags)
"""

import argparse
import struct
import sys
import wave
from pathlib import Path

import numpy as np

try:
    import mutagen
    from mutagen.id3 import ID3, ID3NoHeaderError
    from mutagen.mp3 import MP3
    MUTAGEN_AVAILABLE = True
except ImportError:
    MUTAGEN_AVAILABLE = False


# ── WAV LSB extraction ────────────────────────────────────────────────────────

def extract_wav_lsb(path: Path, channel: str, n_bits: int) -> bytes:
    with wave.open(str(path), "rb") as wf:
        n_channels = wf.getnchannels()
        sampwidth  = wf.getsampwidth()
        n_frames   = wf.getnframes()
        raw        = wf.readframes(n_frames)

    dtype = {1: np.uint8, 2: np.int16, 4: np.int32}.get(sampwidth)
    if dtype is None:
        print(f"[!] Unsupported sample width: {sampwidth} bytes", file=sys.stderr)
        sys.exit(1)

    samples = np.frombuffer(raw, dtype=dtype).astype(np.int64)

    if n_channels == 2:
        if channel == "left":
            samples = samples[0::2]
        elif channel == "right":
            samples = samples[1::2]
        # "both" = keep interleaved

    bits = []
    for s in samples:
        for b in range(n_bits):
            bits.append(int(s >> b) & 1)

    out = bytearray()
    for i in range(0, len(bits) - 7, 8):
        byte = sum(bits[i + j] << j for j in range(8))
        out.append(byte)
    return bytes(out)


# ── MP3 tag + ancillary data extraction ──────────────────────────────────────

def extract_mp3(path: Path) -> None:
    if not MUTAGEN_AVAILABLE:
        print("[!] mutagen not installed: pip install mutagen", file=sys.stderr)
        sys.exit(1)

    print("[*] ID3 tags:")
    try:
        tags = ID3(str(path))
        for key, val in tags.items():
            print(f"  {key}: {val}")
    except ID3NoHeaderError:
        print("  (no ID3 tags found)")

    # Scan for ancillary data / padding in MPEG frames
    data = path.read_bytes()
    pos = 0
    anc_bytes = bytearray()
    frame_count = 0

    while pos < len(data) - 3:
        # Find sync word: 11 set bits = 0xffe or 0xfff at start
        if not (data[pos] == 0xFF and (data[pos + 1] & 0xE0) == 0xE0):
            pos += 1
            continue

        header = struct.unpack(">I", data[pos:pos + 4])[0]
        layer        = (header >> 17) & 3
        bitrate_idx  = (header >> 12) & 0xF
        samplerate_idx = (header >> 10) & 3
        padding      = (header >> 9) & 1

        # Layer 3 (MP3) bitrate table for MPEG1
        br_table = [0, 32, 40, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320, 0]
        sr_table = [44100, 48000, 32000, 0]

        if layer != 1 or bitrate_idx == 0 or bitrate_idx == 15:
            pos += 1
            continue

        bitrate    = br_table[bitrate_idx] * 1000
        samplerate = sr_table[samplerate_idx]
        if samplerate == 0:
            pos += 1
            continue

        frame_size = 144 * bitrate // samplerate + padding
        if frame_size < 4 or pos + frame_size > len(data):
            pos += 1
            continue

        # Ancillary data is after the side information in layer 3
        side_info_size = 32  # simplified (stereo MPEG1)
        anc_start = pos + 4 + side_info_size
        anc_end   = pos + frame_size
        if anc_end > anc_start:
            anc_bytes.extend(data[anc_start:anc_end])

        frame_count += 1
        pos += frame_size

    print(f"\n[*] Scanned {frame_count} MPEG frames")
    if anc_bytes:
        printable = bytes(b for b in anc_bytes if 0x20 <= b < 0x7F)
        if printable:
            print(f"[+] Printable ancillary data ({len(printable)} bytes):")
            print(printable.decode("ascii", errors="replace"))
        else:
            print(f"[*] Ancillary data (hex, first 64): {anc_bytes[:64].hex()}")
    else:
        print("[-] No ancillary data found in frames")


# ── Output helpers ─────────────────────────────────────────────────────────────

def write_output(data: bytes, output: Path | None) -> None:
    if output:
        output.write_bytes(data)
        print(f"[*] {len(data)} bytes written to {output}")
        return
    printable = all(0x20 <= b < 0x7F or b in (0x09, 0x0A, 0x0D) for b in data[:256])
    if printable:
        print(data[:2000].decode("latin-1"))
    else:
        print(f"[*] First 64 bytes (hex): {data[:64].hex()}")
        print("[!] Binary output detected. Use --output to save to file.")


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Extract LSB-hidden data from WAV or MP3 files")
    parser.add_argument("file", help="Audio file (WAV or MP3)")
    parser.add_argument("--channel", default="both", choices=["left", "right", "both"],
                        help="WAV stereo channel (default: both)")
    parser.add_argument("--bits", type=int, default=1, choices=range(1, 9), metavar="N",
                        help="Number of LSBs per sample to extract (default: 1, WAV only)")
    parser.add_argument("--output", help="Write extracted bytes to this file")
    args = parser.parse_args()

    path = Path(args.file)
    if not path.exists():
        print(f"[!] File not found: {path}", file=sys.stderr)
        sys.exit(1)

    ext = path.suffix.lower()
    out = Path(args.output) if args.output else None

    if ext == ".wav":
        print(f"[*] Mode: WAV LSB  channel={args.channel}  bits={args.bits}")
        data = extract_wav_lsb(path, args.channel, args.bits)
        write_output(data, out)
    elif ext == ".mp3":
        print(f"[*] Mode: MP3 tag + ancillary data analysis")
        extract_mp3(path)
    else:
        print(f"[!] Unsupported format: {ext}. Expected .wav or .mp3", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
