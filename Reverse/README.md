# CTF Scripts

## wasm_reverse.py

WASM binary analyser for CTF/RE work. Parses all standard sections, handles `dylink`/`dylink.0` custom sections, and decodes signed LEB128 correctly.

No dependencies — stdlib only.

### Usage

```
python wasm_reverse.py <file.wasm> [flags]
```

Default (no flags): prints a section summary, exports, and dylink metadata if present.

| Flag | Description |
|------|-------------|
| `--imports` | All imports with types and signatures |
| `--exports` | All exports with kind and index |
| `--globals` | Globals with value type, mutability, and init expression |
| `--strings` | Printable strings extracted from data segments |
| `--code` | Per-function analysis (calls, constants, opcode frequencies) |
| `--dylink` | dylink / dylink.0 metadata (memory layout, needed libs) |
| `--all` | All of the above |
| `-j / --json` | Dump full parse as JSON — useful for piping into `jq` |

### Examples

```sh
# Quick overview
python wasm_reverse.py target.wasm

# Find all exported function names
python wasm_reverse.py target.wasm --exports

# Extract strings from data segments (flags, keys, error messages)
python wasm_reverse.py target.wasm --strings

# See what each function calls and what integer constants it uses
python wasm_reverse.py target.wasm --code

# Full dump, filter with jq
python wasm_reverse.py target.wasm -j | jq '.sections[] | select(.name == "export")'

# Everything at once
python wasm_reverse.py target.wasm --all
```

### What gets parsed

- **type** — function signatures (params + results)
- **import / export** — with resolved type signatures for imported functions
- **function** — type index assignments for defined functions
- **global** — value type, mutability, init expression (signed LEB128 decoded)
- **memory / table** — limits
- **data** — raw segments with memory offsets; strings extracted with `--strings`
- **code** — function bodies: outgoing calls, i32/i64 constants, memory op presence, top opcodes by frequency
- **start** — entry point function index
- **name** (custom) — debug symbols: function, local, and global names, used to annotate all other output
- **dylink** (custom) — legacy Emscripten dynamic linking metadata
- **dylink.0** (custom) — modern Emscripten format with subsections for mem info, needed libs, export/import flags

### dylink notes

Emscripten-compiled WASM often includes a `dylink.0` custom section at the start of the file. It contains:

- `mem_size` / `mem_align` — static data segment size and alignment requirements
- `table_size` / `table_align` — function table requirements
- `needed_libs` — shared libraries this module depends on
- `export_info` / `import_info` — per-symbol flags (visibility, binding type)

The script handles both the legacy `dylink` format and the current `dylink.0` subsection format.

### JSON output

`-j` serialises the full parse tree. `bytes` values are hex-encoded strings. Useful for scripting or loading into a notebook.

```sh
# All function names from the name section
python wasm_reverse.py target.wasm -j | jq '.sections[] | select(.custom_name == "name") | .names.functions'

# Constants used in each function body
python wasm_reverse.py target.wasm -j | jq '[.sections[] | select(.name == "code") | .bodies[] | {func: .func_index, consts: .consts}]'
```
