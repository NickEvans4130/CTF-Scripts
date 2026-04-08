#!/usr/bin/env python3
"""
wasm_reverse.py - WASM binary analyser for CTF/RE work

Usage:
    python wasm_reverse.py <file.wasm> [options]

Options:
    --imports       Show imports
    --exports       Show exports
    --globals       Show globals and init values
    --strings       Extract strings from data segments
    --code          Show per-function opcode summary
    --dylink        Show dylink/dylink.0 metadata
    --all           Enable all of the above
    -j, --json      Dump full parse as JSON to stdout
"""

import sys
import os
import struct
import json
import argparse
from collections import Counter

# ── Constants ──────────────────────────────────────────────────────────────────

WASM_MAGIC   = b'\x00asm'
WASM_VERSION = b'\x01\x00\x00\x00'

SECTION_ID = {
    0: "custom",    1: "type",     2: "import",  3: "function",
    4: "table",     5: "memory",   6: "global",  7: "export",
    8: "start",     9: "element", 10: "code",   11: "data",
   12: "datacount",
}

VALTYPE = {
    0x7f: "i32", 0x7e: "i64", 0x7d: "f32", 0x7c: "f64",
    0x7b: "v128", 0x70: "funcref", 0x6f: "externref",
}

EXTTYPE = {0: "func", 1: "table", 2: "memory", 3: "global"}

# Full opcode map including prefixed opcodes (0xfc / 0xfd)
OPCODES = {
    0x00: "unreachable",  0x01: "nop",
    0x02: "block",        0x03: "loop",           0x04: "if",
    0x05: "else",         0x0b: "end",
    0x0c: "br",           0x0d: "br_if",          0x0e: "br_table",
    0x0f: "return",       0x10: "call",            0x11: "call_indirect",
    0x1a: "drop",         0x1b: "select",
    0x20: "local.get",    0x21: "local.set",       0x22: "local.tee",
    0x23: "global.get",   0x24: "global.set",
    0x25: "table.get",    0x26: "table.set",
    0x28: "i32.load",     0x29: "i64.load",        0x2a: "f32.load",
    0x2b: "f64.load",     0x2c: "i32.load8_s",     0x2d: "i32.load8_u",
    0x2e: "i32.load16_s", 0x2f: "i32.load16_u",    0x30: "i64.load8_s",
    0x31: "i64.load8_u",  0x32: "i64.load16_s",    0x33: "i64.load16_u",
    0x34: "i64.load32_s", 0x35: "i64.load32_u",    0x36: "i32.store",
    0x37: "i64.store",    0x38: "f32.store",       0x39: "f64.store",
    0x3a: "i32.store8",   0x3b: "i32.store16",     0x3c: "i64.store8",
    0x3d: "i64.store16",  0x3e: "i64.store32",
    0x3f: "memory.size",  0x40: "memory.grow",
    0x41: "i32.const",    0x42: "i64.const",       0x43: "f32.const",
    0x44: "f64.const",
    0x45: "i32.eqz",      0x46: "i32.eq",          0x47: "i32.ne",
    0x48: "i32.lt_s",     0x49: "i32.lt_u",        0x4a: "i32.gt_s",
    0x4b: "i32.gt_u",     0x4c: "i32.le_s",        0x4d: "i32.le_u",
    0x4e: "i32.ge_s",     0x4f: "i32.ge_u",
    0x50: "i64.eqz",      0x51: "i64.eq",          0x52: "i64.ne",
    0x53: "i64.lt_s",     0x54: "i64.lt_u",        0x55: "i64.gt_s",
    0x56: "i64.gt_u",     0x57: "i64.le_s",        0x58: "i64.le_u",
    0x59: "i64.ge_s",     0x5a: "i64.ge_u",
    0x5b: "f32.eq",       0x5c: "f32.ne",          0x5d: "f32.lt",
    0x5e: "f32.gt",       0x5f: "f32.le",          0x60: "f32.ge",
    0x61: "f64.eq",       0x62: "f64.ne",          0x63: "f64.lt",
    0x64: "f64.gt",       0x65: "f64.le",          0x66: "f64.ge",
    0x67: "i32.clz",      0x68: "i32.ctz",         0x69: "i32.popcnt",
    0x6a: "i32.add",      0x6b: "i32.sub",         0x6c: "i32.mul",
    0x6d: "i32.div_s",    0x6e: "i32.div_u",       0x6f: "i32.rem_s",
    0x70: "i32.rem_u",    0x71: "i32.and",         0x72: "i32.or",
    0x73: "i32.xor",      0x74: "i32.shl",         0x75: "i32.shr_s",
    0x76: "i32.shr_u",    0x77: "i32.rotl",        0x78: "i32.rotr",
    0x79: "i64.clz",      0x7a: "i64.ctz",         0x7b: "i64.popcnt",
    0x7c: "i64.add",      0x7d: "i64.sub",         0x7e: "i64.mul",
    0x7f: "i64.div_s",    0x80: "i64.div_u",       0x81: "i64.rem_s",
    0x82: "i64.rem_u",    0x83: "i64.and",         0x84: "i64.or",
    0x85: "i64.xor",      0x86: "i64.shl",         0x87: "i64.shr_s",
    0x88: "i64.shr_u",    0x89: "i64.rotl",        0x8a: "i64.rotr",
    0x8b: "f32.abs",      0x8c: "f32.neg",         0x8d: "f32.ceil",
    0x8e: "f32.floor",    0x8f: "f32.trunc",       0x90: "f32.nearest",
    0x91: "f32.sqrt",     0x92: "f32.add",         0x93: "f32.sub",
    0x94: "f32.mul",      0x95: "f32.div",         0x96: "f32.min",
    0x97: "f32.max",      0x98: "f32.copysign",
    0x99: "f64.abs",      0x9a: "f64.neg",         0x9b: "f64.ceil",
    0x9c: "f64.floor",    0x9d: "f64.trunc",       0x9e: "f64.nearest",
    0x9f: "f64.sqrt",     0xa0: "f64.add",         0xa1: "f64.sub",
    0xa2: "f64.mul",      0xa3: "f64.div",         0xa4: "f64.min",
    0xa5: "f64.max",      0xa6: "f64.copysign",
    0xa7: "i32.wrap_i64",
    0xa8: "i32.trunc_f32_s",   0xa9: "i32.trunc_f32_u",
    0xaa: "i32.trunc_f64_s",   0xab: "i32.trunc_f64_u",
    0xac: "i64.extend_i32_s",  0xad: "i64.extend_i32_u",
    0xae: "i64.trunc_f32_s",   0xaf: "i64.trunc_f32_u",
    0xb0: "i64.trunc_f64_s",   0xb1: "i64.trunc_f64_u",
    0xb2: "f32.convert_i32_s", 0xb3: "f32.convert_i32_u",
    0xb4: "f32.convert_i64_s", 0xb5: "f32.convert_i64_u",
    0xb6: "f32.demote_f64",
    0xb7: "f64.convert_i32_s", 0xb8: "f64.convert_i32_u",
    0xb9: "f64.convert_i64_s", 0xba: "f64.convert_i64_u",
    0xbb: "f64.promote_f32",
    0xbc: "i32.reinterpret_f32", 0xbd: "i64.reinterpret_f64",
    0xbe: "f32.reinterpret_i32", 0xbf: "f64.reinterpret_i64",
    0xc0: "i32.extend8_s",  0xc1: "i32.extend16_s",
    0xc2: "i64.extend8_s",  0xc3: "i64.extend16_s", 0xc4: "i64.extend32_s",
    0xd0: "ref.null",       0xd1: "ref.is_null",    0xd2: "ref.func",
}

# Misc (0xfc) sub-opcodes
OPCODES_FC = {
    0: "i32.trunc_sat_f32_s", 1: "i32.trunc_sat_f32_u",
    2: "i32.trunc_sat_f64_s", 3: "i32.trunc_sat_f64_u",
    4: "i64.trunc_sat_f32_s", 5: "i64.trunc_sat_f32_u",
    6: "i64.trunc_sat_f64_s", 7: "i64.trunc_sat_f64_u",
    8: "memory.init", 9: "data.drop", 10: "memory.copy", 11: "memory.fill",
    12: "table.init", 13: "elem.drop", 14: "table.copy",
    15: "table.grow", 16: "table.size", 17: "table.fill",
}

# ── LEB128 ─────────────────────────────────────────────────────────────────────

def read_uleb128(data: bytes, pos: int) -> tuple[int, int]:
    """Decode unsigned LEB128. Returns (value, new_pos)."""
    result = 0
    shift = 0
    while True:
        b = data[pos]
        pos += 1
        result |= (b & 0x7f) << shift
        shift += 7
        if not (b & 0x80):
            return result, pos

def read_sleb128(data: bytes, pos: int) -> tuple[int, int]:
    """Decode signed LEB128. Returns (value, new_pos)."""
    result = 0
    shift = 0
    while True:
        b = data[pos]
        pos += 1
        result |= (b & 0x7f) << shift
        shift += 7
        if not (b & 0x80):
            if b & 0x40:
                result |= -(1 << shift)
            return result, pos

# ── Reader ─────────────────────────────────────────────────────────────────────

class Reader:
    """Cursor over a bytes buffer."""

    def __init__(self, data: bytes, pos: int = 0):
        self.data = data
        self.pos  = pos

    def remaining(self) -> int:
        return len(self.data) - self.pos

    def eof(self) -> bool:
        return self.pos >= len(self.data)

    def read_raw(self, n: int) -> bytes:
        if self.remaining() < n:
            raise ValueError(f"Unexpected EOF: need {n}, have {self.remaining()}")
        chunk = self.data[self.pos:self.pos + n]
        self.pos += n
        return chunk

    def read_u8(self) -> int:
        b = self.data[self.pos]
        self.pos += 1
        return b

    def read_u32le(self) -> int:
        v, = struct.unpack_from("<I", self.data, self.pos)
        self.pos += 4
        return v

    def read_f32(self) -> float:
        v, = struct.unpack_from("<f", self.data, self.pos)
        self.pos += 4
        return v

    def read_f64(self) -> float:
        v, = struct.unpack_from("<d", self.data, self.pos)
        self.pos += 8
        return v

    def read_u(self) -> int:
        v, self.pos = read_uleb128(self.data, self.pos)
        return v

    def read_s(self) -> int:
        v, self.pos = read_sleb128(self.data, self.pos)
        return v

    def read_bytes(self) -> bytes:
        n = self.read_u()
        return self.read_raw(n)

    def read_str(self) -> str:
        return self.read_bytes().decode("utf-8", errors="replace")

    def read_valtype(self) -> str:
        b = self.read_u8()
        return VALTYPE.get(b, f"0x{b:02x}")

    def sub(self, n: int) -> "Reader":
        """Return a Reader over the next n bytes, advancing this cursor."""
        chunk = self.read_raw(n)
        return Reader(chunk)


# ── Section parsers ────────────────────────────────────────────────────────────

def parse_type_section(r: Reader) -> list:
    types = []
    for _ in range(r.read_u()):
        tag = r.read_u8()
        if tag != 0x60:
            raise ValueError(f"Expected functype tag 0x60, got 0x{tag:02x}")
        params  = [r.read_valtype() for _ in range(r.read_u())]
        results = [r.read_valtype() for _ in range(r.read_u())]
        types.append({"params": params, "results": results})
    return types


def parse_import_section(r: Reader) -> list:
    imports = []
    for _ in range(r.read_u()):
        module = r.read_str()
        name   = r.read_str()
        kind   = r.read_u8()
        desc   = EXTTYPE.get(kind, f"?{kind}")
        detail = {}
        if kind == 0:       # func: type index
            detail = {"type_idx": r.read_u()}
        elif kind == 1:     # table
            detail = {"reftype": r.read_valtype(), "min": None, "max": None}
            flags = r.read_u8()
            detail["min"] = r.read_u()
            detail["max"] = r.read_u() if flags & 1 else None
        elif kind == 2:     # memory
            flags = r.read_u8()
            detail = {"min": r.read_u()}
            if flags & 1:
                detail["max"] = r.read_u()
        elif kind == 3:     # global
            detail = {"valtype": r.read_valtype(), "mutable": bool(r.read_u8())}
        imports.append({"module": module, "name": name, "kind": desc, **detail})
    return imports


def parse_function_section(r: Reader) -> list:
    return [r.read_u() for _ in range(r.read_u())]


def parse_table_section(r: Reader) -> list:
    tables = []
    for _ in range(r.read_u()):
        reftype = r.read_valtype()
        flags = r.read_u8()
        mn = r.read_u()
        mx = r.read_u() if flags & 1 else None
        tables.append({"reftype": reftype, "min": mn, "max": mx})
    return tables


def parse_memory_section(r: Reader) -> list:
    mems = []
    for _ in range(r.read_u()):
        flags = r.read_u8()
        mn = r.read_u()
        mx = r.read_u() if flags & 1 else None
        mems.append({"min_pages": mn, "max_pages": mx})
    return mems


def _read_init_expr(r: Reader) -> str:
    """Read a constant expression (terminated by 0x0b end), return human string."""
    op = r.read_u8()
    if op == 0x41:
        val = r.read_s()
        r.read_u8()  # end
        return f"i32.const {val}"
    elif op == 0x42:
        val = r.read_s()
        r.read_u8()
        return f"i64.const {val}"
    elif op == 0x43:
        val = r.read_f32()
        r.read_u8()
        return f"f32.const {val}"
    elif op == 0x44:
        val = r.read_f64()
        r.read_u8()
        return f"f64.const {val}"
    elif op == 0x23:
        idx = r.read_u()
        r.read_u8()
        return f"global.get {idx}"
    elif op == 0xd0:
        rtype = r.read_valtype()
        r.read_u8()
        return f"ref.null {rtype}"
    elif op == 0xd2:
        idx = r.read_u()
        r.read_u8()
        return f"ref.func {idx}"
    else:
        # Skip until end (0x0b) for unknown extended exprs
        buf = [f"0x{op:02x}"]
        while not r.eof():
            b = r.read_u8()
            if b == 0x0b:
                break
            buf.append(f"0x{b:02x}")
        return " ".join(buf)


def parse_global_section(r: Reader) -> list:
    globals_ = []
    for _ in range(r.read_u()):
        vt  = r.read_valtype()
        mut = bool(r.read_u8())
        init = _read_init_expr(r)
        globals_.append({"valtype": vt, "mutable": mut, "init": init})
    return globals_


def parse_export_section(r: Reader) -> list:
    exports = []
    for _ in range(r.read_u()):
        name = r.read_str()
        kind = r.read_u8()
        idx  = r.read_u()
        exports.append({"name": name, "kind": EXTTYPE.get(kind, f"?{kind}"), "index": idx})
    return exports


def parse_start_section(r: Reader) -> dict:
    return {"func_index": r.read_u()}


def parse_data_section(r: Reader) -> list:
    segments = []
    for _ in range(r.read_u()):
        flags = r.read_u()
        seg = {"flags": flags}
        if flags == 0:
            seg["offset"] = _read_init_expr(r)
            seg["data"]   = r.read_bytes()
        elif flags == 1:
            # Passive segment (no offset)
            seg["data"] = r.read_bytes()
        elif flags == 2:
            seg["memory_idx"] = r.read_u()
            seg["offset"]     = _read_init_expr(r)
            seg["data"]       = r.read_bytes()
        else:
            seg["data"] = r.read_bytes()
        segments.append(seg)
    return segments


# ── dylink custom sections ──────────────────────────────────────────────────────

def parse_dylink(r: Reader) -> dict:
    """Parse legacy 'dylink' custom section."""
    return {
        "version":      "dylink",
        "mem_size":     r.read_u(),
        "mem_align":    r.read_u(),
        "table_size":   r.read_u(),
        "table_align":  r.read_u(),
        "needed_libs":  [r.read_str() for _ in range(r.read_u())],
    }


def parse_dylink0(r: Reader) -> dict:
    """Parse 'dylink.0' custom section (subsection format)."""
    info = {"version": "dylink.0"}
    while not r.eof():
        tag  = r.read_u()
        sub  = r.sub(r.read_u())
        if tag == 1:   # MEM_INFO
            info["mem_size"]    = sub.read_u()
            info["mem_align"]   = sub.read_u()
            info["table_size"]  = sub.read_u()
            info["table_align"] = sub.read_u()
        elif tag == 2: # NEEDED
            info["needed_libs"] = [sub.read_str() for _ in range(sub.read_u())]
        elif tag == 3: # EXPORT_INFO
            info["export_info"] = [
                {"name": sub.read_str(), "flags": sub.read_u()}
                for _ in range(sub.read_u())
            ]
        elif tag == 4: # IMPORT_INFO
            info["import_info"] = [
                {"module": sub.read_str(), "field": sub.read_str(), "flags": sub.read_u()}
                for _ in range(sub.read_u())
            ]
        else:
            info.setdefault("unknown_subsections", []).append(
                {"tag": tag, "hex": sub.data.hex()}
            )
    return info


# ── names custom section ────────────────────────────────────────────────────────

def parse_names(r: Reader) -> dict:
    """Parse 'name' custom section for debug symbols."""
    names = {}
    while not r.eof():
        sub_id = r.read_u8()
        sub    = r.sub(r.read_u())
        if sub_id == 0:
            names["module"] = sub.read_str()
        elif sub_id == 1:
            names["functions"] = {
                sub.read_u(): sub.read_str() for _ in range(sub.read_u())
            }
        elif sub_id == 2:
            func_locals = {}
            for _ in range(sub.read_u()):
                fi = sub.read_u()
                func_locals[fi] = {sub.read_u(): sub.read_str() for _ in range(sub.read_u())}
            names["locals"] = func_locals
        elif sub_id == 7:
            names["globals"] = {
                sub.read_u(): sub.read_str() for _ in range(sub.read_u())
            }
        elif sub_id == 9:
            names["data_segments"] = {
                sub.read_u(): sub.read_str() for _ in range(sub.read_u())
            }
    return names


# ── Code section / disassembly ─────────────────────────────────────────────────

def disassemble_body(data: bytes) -> dict:
    """
    Walk a function body and return:
      - opcode_counts: Counter of mnemonic -> count
      - calls: list of called function indices
      - consts: list of i32/i64 constants (signed)
      - has_memory_ops: bool
    """
    r = Reader(data)
    opcode_counts = Counter()
    calls   = []
    consts  = []
    mem_ops = False

    while not r.eof():
        try:
            op = r.read_u8()
        except Exception:
            break

        mnem = OPCODES.get(op)

        # Prefixed opcode families
        if op == 0xfc:
            sub = r.read_u()
            mnem = "0xfc." + OPCODES_FC.get(sub, str(sub))
            opcode_counts[mnem] += 1
            # These sub-ops may carry immediates; skip conservatively
            if sub in (8, 10, 11, 12, 14):  # memory.init/copy/fill/table.init/copy
                r.read_u(); r.read_u()
            elif sub in (9, 13, 15, 16, 17):
                r.read_u()
            continue
        elif op == 0xfd:
            # SIMD: just consume the sub-opcode, skip the rest conservatively
            sub = r.read_u()
            opcode_counts[f"v128.{sub}"] += 1
            continue

        if mnem is None:
            opcode_counts[f"0x{op:02x}?"] += 1
            continue

        opcode_counts[mnem] += 1

        # Immediates
        if op in (0x02, 0x03, 0x04):   # block/loop/if: blocktype
            r.read_s()
        elif op == 0x0c or op == 0x0d:  # br / br_if
            r.read_u()
        elif op == 0x0e:                # br_table
            for _ in range(r.read_u() + 1):
                r.read_u()
        elif op == 0x10:                # call
            idx = r.read_u()
            calls.append(idx)
        elif op == 0x11:                # call_indirect
            r.read_u(); r.read_u()
        elif op in (0x1b,):             # select typed
            pass
        elif op in range(0x20, 0x25):   # local/global get/set/tee
            r.read_u()
        elif op in (0x25, 0x26):        # table.get/set
            r.read_u()
        elif op in range(0x28, 0x40):   # memory load/store + size/grow
            if op <= 0x3e:
                r.read_u(); r.read_u()  # align + offset
                mem_ops = True
            else:
                r.read_u()              # memory index (usually 0x00)
        elif op == 0x41:                # i32.const
            consts.append(r.read_s())
        elif op == 0x42:                # i64.const
            consts.append(r.read_s())
        elif op == 0x43:                # f32.const
            r.read_raw(4)
        elif op == 0x44:                # f64.const
            r.read_raw(8)
        elif op in (0xd0,):             # ref.null
            r.read_u8()
        elif op == 0xd2:                # ref.func
            r.read_u()

    return {
        "opcode_counts":  dict(opcode_counts.most_common(20)),
        "calls":          calls,
        "consts":         consts,
        "has_memory_ops": mem_ops,
    }


def parse_code_section(r: Reader) -> list:
    bodies = []
    for _ in range(r.read_u()):
        body_r = r.sub(r.read_u())
        locals_ = []
        for _ in range(body_r.read_u()):
            count = body_r.read_u()
            vt    = body_r.read_valtype()
            locals_.extend([vt] * count)
        code_bytes = body_r.data[body_r.pos:]
        analysis   = disassemble_body(code_bytes)
        bodies.append({"locals": locals_, **analysis})
    return bodies


# ── Strings from data ──────────────────────────────────────────────────────────

def extract_strings(data: bytes, min_len: int = 4) -> list:
    pattern = rb'[ -~]{' + str(min_len).encode() + rb',}'
    return [m.group().decode("ascii") for m in __import__("re").finditer(pattern, data)]


# ── Top-level parser ───────────────────────────────────────────────────────────

def parse_wasm(path: str) -> dict:
    with open(path, "rb") as f:
        raw = f.read()

    if raw[:4] != WASM_MAGIC:
        raise ValueError("Not a WASM file (bad magic)")
    if raw[4:8] != WASM_VERSION:
        raise ValueError(f"Unsupported WASM version: {raw[4:8].hex()}")

    result = {
        "file":     os.path.basename(path),
        "size":     len(raw),
        "sections": [],
    }

    r = Reader(raw, 8)

    type_section   = []
    import_section = []
    func_types     = []

    while not r.eof():
        sec_id   = r.read_u8()
        sec_r    = r.sub(r.read_u())
        sec_name = SECTION_ID.get(sec_id, f"unknown_{sec_id}")
        entry    = {"id": sec_id, "name": sec_name, "offset": sec_r.pos - len(sec_r.data)}

        try:
            if sec_id == 0:     # custom
                name = sec_r.read_str()
                entry["custom_name"] = name
                content_r = Reader(sec_r.data[sec_r.pos:])
                if name == "dylink":
                    entry["dylink"] = parse_dylink(content_r)
                elif name == "dylink.0":
                    entry["dylink"] = parse_dylink0(content_r)
                elif name == "name":
                    entry["names"] = parse_names(content_r)
                else:
                    entry["raw_hex"] = sec_r.data[sec_r.pos:].hex()
            elif sec_id == 1:
                entry["types"] = parse_type_section(sec_r)
                type_section   = entry["types"]
            elif sec_id == 2:
                entry["imports"] = parse_import_section(sec_r)
                import_section   = entry["imports"]
            elif sec_id == 3:
                entry["func_type_indices"] = parse_function_section(sec_r)
                func_types = entry["func_type_indices"]
            elif sec_id == 4:
                entry["tables"] = parse_table_section(sec_r)
            elif sec_id == 5:
                entry["memories"] = parse_memory_section(sec_r)
            elif sec_id == 6:
                entry["globals"] = parse_global_section(sec_r)
            elif sec_id == 7:
                entry["exports"] = parse_export_section(sec_r)
            elif sec_id == 8:
                entry["start"] = parse_start_section(sec_r)
            elif sec_id == 10:
                import_func_count = sum(1 for i in import_section if i["kind"] == "func")
                bodies = parse_code_section(sec_r)
                for i, body in enumerate(bodies):
                    body["func_index"]   = import_func_count + i
                    type_idx = func_types[i] if i < len(func_types) else None
                    body["type_idx"]     = type_idx
                    if type_idx is not None and type_idx < len(type_section):
                        body["signature"] = type_section[type_idx]
                entry["bodies"] = bodies
            elif sec_id == 11:
                entry["data_segments"] = parse_data_section(sec_r)
            elif sec_id == 12:
                entry["datacount"] = sec_r.read_u()
        except Exception as e:
            entry["parse_error"] = str(e)

        result["sections"].append(entry)

    return result


# ── Pretty printers ────────────────────────────────────────────────────────────

def _sig(t: dict) -> str:
    params  = ", ".join(t["params"])  if t["params"]  else ""
    results = ", ".join(t["results"]) if t["results"] else ""
    return f"({params}) -> ({results})"


def print_summary(parsed: dict, args):
    p = print
    sections = parsed["sections"]

    p(f"\n=== {parsed['file']}  ({parsed['size']} bytes) ===\n")

    # Collect resolved sections for easy access
    by_name = {}
    for s in sections:
        n = s.get("custom_name", s["name"])
        by_name.setdefault(n, []).append(s)

    def get(name):
        return by_name.get(name, [{}])[0]

    types     = get("type").get("types", [])
    imports   = get("import").get("imports", [])
    exports   = get("export").get("exports", [])
    globals_  = get("global").get("globals", [])
    memories  = get("memory").get("memories", [])
    bodies    = get("code").get("bodies", [])
    data_segs = get("data").get("data_segments", [])
    start     = get("start").get("start")

    func_names = {}
    for s in sections:
        if s.get("custom_name") == "name":
            func_names = {int(k): v for k, v in s.get("names", {}).get("functions", {}).items()}

    # Stats
    import_funcs = [i for i in imports if i["kind"] == "func"]
    p(f"  Types:        {len(types)}")
    p(f"  Imports:      {len(imports)}  ({len(import_funcs)} funcs)")
    p(f"  Functions:    {len(bodies)}  (defined)")
    p(f"  Exports:      {len(exports)}")
    p(f"  Globals:      {len(globals_)}")
    p(f"  Memories:     {len(memories)}")
    p(f"  Data segs:    {len(data_segs)}")
    if start:
        p(f"  Start func:   {start['func_index']}")

    # dylink
    dylink_info = None
    for s in sections:
        if "dylink" in s:
            dylink_info = s["dylink"]
            break

    if dylink_info and (args.dylink or args.all):
        p("\n--- dylink ---")
        p(f"  Format:      {dylink_info.get('version')}")
        p(f"  mem_size:    {dylink_info.get('mem_size')}")
        p(f"  mem_align:   {dylink_info.get('mem_align')}")
        p(f"  table_size:  {dylink_info.get('table_size')}")
        p(f"  table_align: {dylink_info.get('table_align')}")
        libs = dylink_info.get("needed_libs", [])
        if libs:
            p(f"  needed_libs: {libs}")
        ei = dylink_info.get("export_info", [])
        if ei:
            p(f"  export_info ({len(ei)}):")
            for e in ei:
                p(f"    {e['name']}  flags=0x{e['flags']:x}")
        ii = dylink_info.get("import_info", [])
        if ii:
            p(f"  import_info ({len(ii)}):")
            for e in ii:
                p(f"    {e['module']}.{e['field']}  flags=0x{e['flags']:x}")

    if args.imports or args.all:
        p("\n--- imports ---")
        for i, imp in enumerate(imports):
            detail = ""
            if imp["kind"] == "func":
                ti = imp.get("type_idx")
                if ti is not None and ti < len(types):
                    detail = f"  {_sig(types[ti])}"
            elif imp["kind"] == "memory":
                detail = f"  min={imp.get('min')} max={imp.get('max')}"
            elif imp["kind"] == "global":
                detail = f"  {imp.get('valtype')} {'mut' if imp.get('mutable') else 'const'}"
            p(f"  [{i:4d}] {imp['module']}.{imp['name']}  ({imp['kind']}){detail}")

    if args.exports or args.all:
        p("\n--- exports ---")
        for exp in exports:
            name = func_names.get(exp["index"], "")
            alias = f"  [{name}]" if name and name != exp["name"] else ""
            p(f"  {exp['name']}  {exp['kind']}[{exp['index']}]{alias}")

    if args.globals or args.all:
        p("\n--- globals ---")
        for i, g in enumerate(globals_):
            name = func_names.get(i, "")
            p(f"  [{i:4d}] {g['valtype']} {'mut' if g['mutable'] else 'const'}  = {g['init']}  {name}")

    if (args.exports or args.all) and memories:
        p("\n--- memory ---")
        for i, m in enumerate(memories):
            pages_max = f" max={m['max_pages']}" if m["max_pages"] is not None else ""
            p(f"  [{i}] min={m['min_pages']} pages ({m['min_pages']*64}KB){pages_max}")

    if args.strings or args.all:
        p("\n--- strings from data segments ---")
        all_strings = []
        for seg in data_segs:
            d = seg.get("data", b"")
            offset_expr = seg.get("offset", "passive")
            for s in extract_strings(d):
                all_strings.append((offset_expr, s))
        if all_strings:
            for offset_expr, s in all_strings:
                p(f"  @{offset_expr}: {repr(s)}")
        else:
            p("  (none found)")

    if args.code or args.all:
        import_func_count = len(import_funcs)
        p("\n--- function bodies ---")
        for body in bodies:
            fi   = body["func_index"]
            name = func_names.get(fi, f"func_{fi}")
            sig  = _sig(body["signature"]) if "signature" in body else "?"
            p(f"\n  [{fi}] {name}  {sig}")
            if body["locals"]:
                p(f"    locals: {body['locals']}")
            if body["calls"]:
                resolved = []
                for ci in body["calls"]:
                    cn = func_names.get(ci, str(ci))
                    resolved.append(cn)
                p(f"    calls:  {resolved}")
            if body["consts"]:
                p(f"    consts: {body['consts'][:20]}")
            if body["has_memory_ops"]:
                p(f"    memory ops: yes")
            top = list(body["opcode_counts"].items())[:10]
            p(f"    top opcodes: {top}")


# ── Entry point ────────────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser(description="WASM binary analyser")
    ap.add_argument("file",                    help="Input .wasm file")
    ap.add_argument("--imports",  action="store_true")
    ap.add_argument("--exports",  action="store_true")
    ap.add_argument("--globals",  action="store_true")
    ap.add_argument("--strings",  action="store_true")
    ap.add_argument("--code",     action="store_true")
    ap.add_argument("--dylink",   action="store_true")
    ap.add_argument("--all",      action="store_true", help="Enable all views")
    ap.add_argument("-j", "--json", action="store_true", help="Dump JSON to stdout")
    args = ap.parse_args()

    if not os.path.isfile(args.file):
        print(f"error: file not found: {args.file}", file=sys.stderr)
        sys.exit(1)

    parsed = parse_wasm(args.file)

    if args.json:
        # bytes objects are not JSON-serialisable; encode as hex
        def default(o):
            if isinstance(o, bytes):
                return o.hex()
            raise TypeError(repr(o))
        print(json.dumps(parsed, indent=2, default=default))
        return

    # Default: show summary + whatever flags were requested
    if not any([args.imports, args.exports, args.globals,
                args.strings, args.code, args.dylink]):
        # No flags given -- show summary only and hint
        print_summary(parsed, argparse.Namespace(
            imports=False, exports=True, globals=False,
            strings=False, code=False, dylink=True, all=False))
        print("\n  (use --all or individual flags for more detail)")
    else:
        print_summary(parsed, args)


if __name__ == "__main__":
    main()
