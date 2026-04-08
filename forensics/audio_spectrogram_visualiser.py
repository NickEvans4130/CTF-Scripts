#!/usr/bin/env python3
"""
Audio spectrogram visualiser with DTMF and Morse code decoding.
Requires: numpy, scipy, matplotlib
Optional: librosa (for MP3 support)
"""

import argparse
import sys
import wave
from pathlib import Path

import numpy as np
from scipy import signal
from scipy.io import wavfile
import matplotlib.pyplot as plt


# ── DTMF frequency table ──────────────────────────────────────────────────────

DTMF_TABLE = {
    (697, 1209): "1", (697, 1336): "2", (697, 1477): "3", (697, 1633): "A",
    (770, 1209): "4", (770, 1336): "5", (770, 1477): "6", (770, 1633): "B",
    (852, 1209): "7", (852, 1336): "8", (852, 1477): "9", (852, 1633): "C",
    (941, 1209): "*", (941, 1336): "0", (941, 1477): "#", (941, 1633): "D",
}
DTMF_LOW  = [697, 770, 852, 941]
DTMF_HIGH = [1209, 1336, 1477, 1633]
DTMF_TOL  = 20  # Hz tolerance


def load_audio(path: Path) -> tuple[np.ndarray, int]:
    """Load audio file. Supports WAV natively, MP3 via librosa."""
    ext = path.suffix.lower()
    if ext == ".wav":
        rate, data = wavfile.read(str(path))
        if data.ndim > 1:
            data = data[:, 0]  # take left channel
        data = data.astype(np.float32)
        return data, rate
    else:
        try:
            import librosa
            data, rate = librosa.load(str(path), sr=None, mono=True)
            return data, int(rate)
        except ImportError:
            print("[!] librosa required for non-WAV files: pip install librosa", file=sys.stderr)
            sys.exit(1)


# ── Spectrogram ───────────────────────────────────────────────────────────────

def show_spectrogram(data: np.ndarray, rate: int, output: Path | None) -> None:
    fig, ax = plt.subplots(figsize=(14, 6))
    ax.specgram(data, Fs=rate, NFFT=1024, noverlap=512, cmap="inferno")
    ax.set_xlabel("Time (s)")
    ax.set_ylabel("Frequency (Hz)")
    ax.set_title("Spectrogram")
    plt.tight_layout()
    if output:
        fig.savefig(output, dpi=150)
        print(f"[*] Spectrogram saved to {output}")
    else:
        plt.show()


# ── DTMF decoder ─────────────────────────────────────────────────────────────

def nearest(freq: float, candidates: list) -> int:
    return min(candidates, key=lambda f: abs(f - freq))


def decode_dtmf(data: np.ndarray, rate: int) -> str:
    frame_size = int(rate * 0.04)  # 40 ms frames
    step = int(rate * 0.02)        # 20 ms step
    digits = []
    last = None

    for start in range(0, len(data) - frame_size, step):
        frame = data[start:start + frame_size]
        freqs = np.fft.rfftfreq(len(frame), d=1.0 / rate)
        mag   = np.abs(np.fft.rfft(frame))

        # Find dominant low and high frequency
        low_mask  = (freqs >= 600) & (freqs <= 1000)
        high_mask = (freqs >= 1100) & (freqs <= 1700)

        if not low_mask.any() or not high_mask.any():
            last = None
            continue

        low_freq  = freqs[low_mask][np.argmax(mag[low_mask])]
        high_freq = freqs[high_mask][np.argmax(mag[high_mask])]

        low_near  = nearest(low_freq,  DTMF_LOW)
        high_near = nearest(high_freq, DTMF_HIGH)

        if abs(low_freq - low_near) < DTMF_TOL and abs(high_freq - high_near) < DTMF_TOL:
            digit = DTMF_TABLE.get((low_near, high_near))
            if digit and digit != last:
                digits.append(digit)
                last = digit
        else:
            last = None

    return "".join(digits)


# ── Morse decoder ─────────────────────────────────────────────────────────────

MORSE_CODE = {
    ".-": "A", "-...": "B", "-.-.": "C", "-..": "D", ".": "E",
    "..-.": "F", "--.": "G", "....": "H", "..": "I", ".---": "J",
    "-.-": "K", ".-..": "L", "--": "M", "-.": "N", "---": "O",
    ".--.": "P", "--.-": "Q", ".-.": "R", "...": "S", "-": "T",
    "..-": "U", "...-": "V", ".--": "W", "-..-": "X", "-.--": "Y",
    "--..": "Z", "-----": "0", ".----": "1", "..---": "2",
    "...--": "3", "....-": "4", ".....": "5", "-....": "6",
    "--...": "7", "---..": "8", "----.": "9",
}


def decode_morse(data: np.ndarray, rate: int) -> str:
    """Basic energy-threshold Morse decoder."""
    frame = 256
    energy = np.array([
        np.sum(data[i:i + frame] ** 2) for i in range(0, len(data), frame)
    ])
    threshold = energy.mean()
    on_off = energy > threshold

    # Count run lengths
    runs = []
    i = 0
    while i < len(on_off):
        val = on_off[i]
        count = 0
        while i < len(on_off) and on_off[i] == val:
            count += 1
            i += 1
        runs.append((bool(val), count))

    if not runs:
        return ""

    # Estimate dot length as the shortest ON run
    on_lengths = [c for v, c in runs if v]
    if not on_lengths:
        return ""
    dot = min(on_lengths)

    symbols = []
    for is_on, count in runs:
        units = max(1, round(count / dot))
        if is_on:
            symbols.append("." if units <= 2 else "-")
        else:
            if units >= 7:
                symbols.append(" / ")  # word gap
            elif units >= 3:
                symbols.append(" ")   # letter gap

    morse_str = "".join(symbols)
    words = morse_str.split(" / ")
    decoded = []
    for word in words:
        letters = []
        for letter_code in word.strip().split(" "):
            letters.append(MORSE_CODE.get(letter_code, "?"))
        decoded.append("".join(letters))
    return " ".join(decoded)


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Audio spectrogram visualiser with DTMF/Morse decoding")
    parser.add_argument("file", help="Audio file (WAV, MP3, etc.)")
    parser.add_argument("--mode", choices=["spectrogram", "dtmf", "morse", "all"],
                        default="spectrogram", help="Analysis mode (default: spectrogram)")
    parser.add_argument("--output", help="Save spectrogram image to file")
    args = parser.parse_args()

    path = Path(args.file)
    if not path.exists():
        print(f"[!] File not found: {path}", file=sys.stderr)
        sys.exit(1)

    print(f"[*] Loading {path} ...")
    data, rate = load_audio(path)
    duration = len(data) / rate
    print(f"[*] Sample rate: {rate} Hz  Duration: {duration:.2f}s  Samples: {len(data):,}")

    out = Path(args.output) if args.output else None

    if args.mode in ("spectrogram", "all"):
        show_spectrogram(data, rate, out)

    if args.mode in ("dtmf", "all"):
        print("\n[*] Decoding DTMF tones ...")
        digits = decode_dtmf(data, rate)
        print(f"[+] DTMF decoded: {digits!r}" if digits else "[-] No DTMF tones detected")

    if args.mode in ("morse", "all"):
        print("\n[*] Decoding Morse code ...")
        text = decode_morse(data, rate)
        print(f"[+] Morse decoded: {text!r}" if text else "[-] No Morse pattern detected")


if __name__ == "__main__":
    main()
