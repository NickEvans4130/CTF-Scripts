#!/usr/bin/env python3
"""
PDF hidden layer, metadata, annotation, and attachment extractor.
Requires: PyMuPDF (pip install pymupdf)
"""

import argparse
import sys
from pathlib import Path

try:
    import fitz  # PyMuPDF
except ImportError:
    print("[!] PyMuPDF not installed: pip install pymupdf", file=sys.stderr)
    sys.exit(1)


def extract_metadata(doc: fitz.Document) -> None:
    print("[*] Metadata")
    print("=" * 60)
    meta = doc.metadata
    for key, val in meta.items():
        if val:
            print(f"  {key}: {val}")

    # XMP metadata
    xmp = doc.get_xml_metadata()
    if xmp:
        print(f"\n  XMP metadata ({len(xmp)} bytes):")
        print(xmp[:2000])


def extract_layers(doc: fitz.Document, out_dir: Path | None) -> None:
    print("[*] Text content per page (all layers)")
    print("=" * 60)
    for page_num in range(len(doc)):
        page = doc[page_num]
        # Extract text with all details including hidden/white text
        blocks = page.get_text("dict")["blocks"]
        hidden_spans = []
        for block in blocks:
            if block.get("type") != 0:
                continue
            for line in block.get("lines", []):
                for span in line.get("spans", []):
                    text = span.get("text", "").strip()
                    if not text:
                        continue
                    color = span.get("color", 0)
                    # White text on white background is common hiding technique
                    if color in (0xFFFFFF, 16777215):
                        hidden_spans.append(text)
                    print(f"  p{page_num+1}: {text!r}  color=#{color:06x}")

        if hidden_spans:
            print(f"\n  [!] Potentially hidden (white) text on page {page_num+1}:")
            for s in hidden_spans:
                print(f"    {s!r}")

    # Also dump full raw text per page to output dir
    if out_dir:
        out_dir.mkdir(parents=True, exist_ok=True)
        for page_num in range(len(doc)):
            text = doc[page_num].get_text()
            (out_dir / f"page_{page_num+1}.txt").write_text(text)
        print(f"\n[*] Page text saved to {out_dir}")


def extract_attachments(doc: fitz.Document, out_dir: Path | None) -> None:
    print("[*] Embedded Attachments")
    print("=" * 60)
    found = 0

    # EmbeddedFiles in the catalog
    names = doc.embfile_names()
    for name in names:
        info = doc.embfile_info(name)
        data = doc.embfile_get(name)
        print(f"  [{found}] {name}  ({len(data):,} bytes)  created={info.get('creationDate','?')}")
        if out_dir:
            out_dir.mkdir(parents=True, exist_ok=True)
            out_path = out_dir / name
            out_path.write_bytes(data)
            print(f"       -> {out_path}")
        found += 1

    # Annotations with FileAttachment subtype
    for page_num in range(len(doc)):
        page = doc[page_num]
        for annot in page.annots():
            if annot.type[1] == "FileAttachment":
                fs = annot.file_info()
                data = annot.file_get()
                name = fs.get("filename", f"attachment_{found}")
                print(f"  [{found}] {name}  ({len(data):,} bytes)  page={page_num+1}")
                if out_dir:
                    out_dir.mkdir(parents=True, exist_ok=True)
                    (out_dir / name).write_bytes(data)
                found += 1

    if not found:
        print("  (no attachments found)")


def extract_javascript(doc: fitz.Document) -> None:
    print("[*] JavaScript")
    print("=" * 60)
    found = False
    for name in doc.get_javascript_names() if hasattr(doc, "get_javascript_names") else []:
        js = doc.get_javascript(name)
        print(f"  Name: {name}\n{js}\n")
        found = True

    # Also check page annotations for JS actions
    for page_num in range(len(doc)):
        for annot in doc[page_num].annots():
            action = annot.info.get("action", "")
            if "JavaScript" in str(action) or "JS" in str(action):
                print(f"  Annotation JS on page {page_num+1}: {action}")
                found = True

    if not found:
        print("  (no JavaScript found)")


def main():
    parser = argparse.ArgumentParser(description="Extract metadata, hidden layers, and attachments from PDFs")
    parser.add_argument("file", help="PDF file")
    parser.add_argument("--metadata",    action="store_true", help="Extract metadata")
    parser.add_argument("--layers",      action="store_true", help="Extract text layers (including hidden)")
    parser.add_argument("--attachments", action="store_true", help="Extract embedded file attachments")
    parser.add_argument("--javascript",  action="store_true", help="Dump JavaScript")
    parser.add_argument("--all",         action="store_true", help="Run all extractions")
    parser.add_argument("--output",      help="Directory for extracted files/layers")
    args = parser.parse_args()

    path = Path(args.file)
    if not path.exists():
        print(f"[!] File not found: {path}", file=sys.stderr)
        sys.exit(1)

    doc = fitz.open(str(path))
    print(f"[*] {path.name}  pages={len(doc)}  encrypted={doc.is_encrypted}\n")

    out = Path(args.output) if args.output else None
    run_all = args.all or not any([args.metadata, args.layers, args.attachments, args.javascript])

    if args.metadata or run_all:
        extract_metadata(doc)
        print()
    if args.layers or run_all:
        extract_layers(doc, out / "layers" if out else None)
        print()
    if args.attachments or run_all:
        extract_attachments(doc, out / "attachments" if out else None)
        print()
    if args.javascript or run_all:
        extract_javascript(doc)


if __name__ == "__main__":
    main()
