#!/usr/bin/env python3
"""
Office document macro, metadata, and hidden content extractor.
Supports OOXML (docx/xlsx/pptx) and legacy OLE (doc/xls) formats.
Requires: oletools (pip install oletools), python-docx (pip install python-docx)
"""

import argparse
import sys
import zipfile
from pathlib import Path

try:
    from oletools.olevba import VBA_Parser
    OLETOOLS_AVAILABLE = True
except ImportError:
    OLETOOLS_AVAILABLE = False


OOXML_EXTS = {".docx", ".xlsx", ".pptx", ".xlsm", ".docm", ".pptm"}
OLE_EXTS   = {".doc", ".xls", ".ppt"}


# ── Macros ────────────────────────────────────────────────────────────────────

def extract_macros(path: Path) -> None:
    if not OLETOOLS_AVAILABLE:
        print("[!] oletools not installed: pip install oletools", file=sys.stderr)
        return

    print("[*] VBA Macros")
    print("=" * 60)
    vba = VBA_Parser(str(path))
    if not vba.detect_vba_macros():
        print("  (no VBA macros found)")
        return

    for (filename, stream_path, vba_filename, vba_code) in vba.extract_macros():
        print(f"\n  -- {vba_filename} (stream: {stream_path})")
        print(vba_code)

    print("\n[*] Suspicious keywords:")
    results = vba.analyze_macros()
    for (type_, keyword, description) in results:
        print(f"  [{type_}] {keyword}: {description}")


# ── OOXML metadata ────────────────────────────────────────────────────────────

def extract_ooxml_metadata(path: Path) -> None:
    print("[*] OOXML Metadata (core.xml / app.xml)")
    print("=" * 60)
    with zipfile.ZipFile(path) as zf:
        for xml_path in ("docProps/core.xml", "docProps/app.xml"):
            try:
                content = zf.read(xml_path).decode("utf-8", errors="replace")
                print(f"\n  [{xml_path}]")
                print(content)
            except KeyError:
                pass


def unzip_ooxml(path: Path, out_dir: Path) -> None:
    print(f"[*] Unzipping OOXML to {out_dir}")
    out_dir.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(path) as zf:
        zf.extractall(out_dir)
    print(f"    {len(zf.namelist())} entries extracted")

    # Look for hidden/suspicious XML content
    print("\n[*] Scanning XML for interesting strings ...")
    import re
    flag_re = re.compile(r"(?:flag|ctf|htb|key|secret|password)[^<\"]{0,200}", re.IGNORECASE)
    for f in out_dir.rglob("*.xml"):
        text = f.read_text(errors="ignore")
        for match in flag_re.finditer(text):
            print(f"  [{f.relative_to(out_dir)}] {match.group()!r}")


# ── OLE metadata ─────────────────────────────────────────────────────────────

def extract_ole_metadata(path: Path) -> None:
    try:
        import olefile
    except ImportError:
        print("[!] olefile not installed: pip install olefile", file=sys.stderr)
        return

    print("[*] OLE Metadata")
    print("=" * 60)
    with olefile.OleFileIO(str(path)) as ole:
        meta = ole.get_metadata()
        fields = [
            "author", "last_saved_by", "create_time", "last_saved_time",
            "title", "subject", "company", "manager", "revision_num",
        ]
        for f in fields:
            val = getattr(meta, f, None)
            if val:
                print(f"  {f}: {val}")

        print("\n  Directory streams:")
        for entry in ole.listdir():
            print(f"    {'\\'.join(entry)}")


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Extract macros, metadata, and hidden content from Office documents")
    parser.add_argument("file", help="Office document (docx, xlsx, pptx, doc, xls)")
    parser.add_argument("--macros",   action="store_true", help="Extract VBA macros")
    parser.add_argument("--metadata", action="store_true", help="Extract document metadata")
    parser.add_argument("--unzip",    metavar="DIR",       help="Unzip OOXML and scan XML (OOXML only)")
    parser.add_argument("--all",      action="store_true", help="Run all extractions")
    args = parser.parse_args()

    path = Path(args.file)
    if not path.exists():
        print(f"[!] File not found: {path}", file=sys.stderr)
        sys.exit(1)

    ext = path.suffix.lower()
    is_ooxml = ext in OOXML_EXTS
    is_ole   = ext in OLE_EXTS

    print(f"[*] File: {path}  format={'OOXML' if is_ooxml else 'OLE' if is_ole else 'unknown'}\n")

    run_all = args.all or not any([args.macros, args.metadata, args.unzip])

    if args.macros or run_all:
        extract_macros(path)
        print()

    if args.metadata or run_all:
        if is_ooxml:
            extract_ooxml_metadata(path)
        elif is_ole:
            extract_ole_metadata(path)
        print()

    if args.unzip:
        if not is_ooxml:
            print("[!] --unzip only works with OOXML formats (docx/xlsx/pptx)")
        else:
            unzip_ooxml(path, Path(args.unzip))


if __name__ == "__main__":
    main()
