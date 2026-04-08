#!/usr/bin/env python3
"""
Steganography detector - LSB analysis and chi-square test for hidden data in images.
"""

import argparse
import sys
from pathlib import Path

import numpy as np
from PIL import Image
from scipy.stats import chisquare


def load_image(path: Path) -> np.ndarray:
    img = Image.open(path).convert("RGB")
    return np.array(img)


def lsb_visualise(arr: np.ndarray, channel: int, output: Path | None) -> None:
    """Amplify LSBs of a single channel to make hidden patterns visible."""
    lsb = (arr[:, :, channel] & 1) * 255
    vis = Image.fromarray(lsb.astype(np.uint8))
    if output:
        vis.save(output)
        print(f"[*] LSB visualisation saved to {output}")
    else:
        vis.show()


def chi_square_test(arr: np.ndarray) -> None:
    """
    Chi-square test on the LSB distribution of each channel.
    For a clean image, pairs of neighbouring byte values (2k, 2k+1) should
    appear with similar frequency. Steg tends to equalise them.
    """
    channel_names = ["Red", "Green", "Blue"]
    print("\n[*] Chi-square test (LSB pairs per channel)")
    print(f"{'Channel':<10} {'Chi2':>12} {'p-value':>12} {'Verdict'}")
    print("-" * 55)
    for i, name in enumerate(channel_names):
        flat = arr[:, :, i].flatten().astype(np.uint64)
        # Count occurrences of even (2k) and odd (2k+1) values for each pair
        observed = np.zeros(128)
        expected = np.zeros(128)
        counts = np.bincount(flat, minlength=256)
        for k in range(128):
            observed[k] = counts[2 * k] + counts[2 * k + 1]
            expected[k] = observed[k]  # under H0, even/odd equally likely after steg
        # Refine: compare even vs odd within each pair
        even_counts = counts[0::2]
        odd_counts  = counts[1::2]
        chi2, p = chisquare(even_counts, f_exp=odd_counts + 1e-9)
        verdict = "SUSPICIOUS (possible steg)" if p < 0.05 else "OK"
        print(f"{name:<10} {chi2:>12.4f} {p:>12.6f} {verdict}")


def lsb_entropy(arr: np.ndarray) -> None:
    """Print LSB bit ratio per channel; ~0.5 suggests steg, far from 0.5 suggests clean."""
    channel_names = ["Red", "Green", "Blue"]
    print("\n[*] LSB bit ratio per channel (expected ~0.5 for steg, natural images vary)")
    for i, name in enumerate(channel_names):
        flat = arr[:, :, i].flatten()
        lsbs = flat & 1
        ratio = lsbs.mean()
        print(f"  {name}: {ratio:.4f}")


def main():
    parser = argparse.ArgumentParser(description="Detect LSB steganography in images")
    parser.add_argument("file", help="Image file to analyse")
    parser.add_argument("--chi-square", action="store_true", help="Run chi-square test on LSB distribution")
    parser.add_argument("--lsb-visualise", action="store_true", help="Generate LSB visualisation image")
    parser.add_argument("--channel", choices=["R", "G", "B"], default="G",
                        help="Channel to visualise (default: G)")
    parser.add_argument("--output", help="Output path for visualisation image")
    args = parser.parse_args()

    path = Path(args.file)
    if not path.exists():
        print(f"[!] File not found: {path}", file=sys.stderr)
        sys.exit(1)

    arr = load_image(path)
    print(f"[*] Image: {path.name}  size={arr.shape[1]}x{arr.shape[0]}  mode=RGB")

    lsb_entropy(arr)

    if args.chi_square:
        chi_square_test(arr)

    if args.lsb_visualise:
        ch_idx = {"R": 0, "G": 1, "B": 2}[args.channel]
        out = Path(args.output) if args.output else None
        lsb_visualise(arr, ch_idx, out)


if __name__ == "__main__":
    main()
