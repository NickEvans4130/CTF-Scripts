# Miscellaneous / Utility

General-purpose CTF utility scripts for data analysis, encoding, and workflow automation.

---

## Scripts

### [entropy_calculator.py](entropy_calculator.py)

**Summary:** Calculates Shannon entropy per byte offset across a file to detect encrypted, compressed, or high-entropy regions.

**Use cases:**
- Identify encrypted payloads or compressed blobs embedded within larger files
- Visualise entropy as a plot to locate interesting regions before carving
- Compare entropy profiles between known-plaintext and unknown sections

**Usage:**
```
python entropy_calculator.py <file>
python entropy_calculator.py binary.bin --block-size 256 --plot
python entropy_calculator.py binary.bin --threshold 7.5 --highlight
```

**Dependencies:** `numpy`, `matplotlib`

---

### [hex_dump_viewer.py](hex_dump_viewer.py)

**Summary:** Displays a hex dump of a file with an ASCII sidebar, similar to `xxd` or `hexdump -C`.

**Use cases:**
- Visually inspect binary file contents for magic bytes, strings, or patterns
- Configurable byte width, offset display, and colour highlighting
- Pipe-friendly: accepts stdin and outputs to stdout

**Usage:**
```
python hex_dump_viewer.py <file>
python hex_dump_viewer.py binary.bin
python hex_dump_viewer.py binary.bin --width 32 --offset 0x100 --length 0x200
cat binary.bin | python hex_dump_viewer.py -
```

**Dependencies:** None

---

### [byte_frequency_analyser.py](byte_frequency_analyser.py)

**Summary:** Counts and visualises the frequency of each byte value in a file.

**Use cases:**
- Detect XOR encryption (flat distribution) vs compression (non-uniform)
- Identify the most common byte for single-byte XOR key guessing (XOR with 0x20 for space)
- Compare frequency profiles between encoded and plaintext sections

**Usage:**
```
python byte_frequency_analyser.py <file>
python byte_frequency_analyser.py cipher.bin --plot
python byte_frequency_analyser.py cipher.bin --top 10 --output freq.csv
```

**Dependencies:** `collections`, `matplotlib`

---

### [charset_detector.py](charset_detector.py)

**Summary:** Detects the character set and encoding of a text file (UTF-8, Latin-1, UTF-16, etc.).

**Use cases:**
- Determine the encoding of a text file before processing it
- Detect BOM markers and encoding declarations in HTML/XML
- Compare detected vs declared encoding to find discrepancies

**Usage:**
```
python charset_detector.py <file>
python charset_detector.py mystery.txt
python charset_detector.py mystery.txt --confidence
```

**Dependencies:** `chardet` or `charset-normalizer`

---

### [string_encoder.py](string_encoder.py)

**Summary:** Converts a string to and from URL encoding, HTML entities, Unicode escapes, and hexadecimal.

**Use cases:**
- Quickly encode a payload for injection into URL or HTML contexts
- Decode multiple encoding layers to find a hidden message
- Generate all encoding variants for bypass testing

**Usage:**
```
python string_encoder.py --input "<script>alert(1)</script>" --mode url
python string_encoder.py --input "flag{test}" --mode all
python string_encoder.py --input "%3Cscript%3E" --decode --mode url
```

**Dependencies:** `urllib.parse`, `html`

---

### [qr_codec.py](qr_codec.py)

**Summary:** Generates QR codes from text and decodes QR codes from image files.

**Use cases:**
- Decode a QR code image provided as part of a CTF challenge
- Generate a QR code for testing or encoding a payload
- Handle damaged or low-contrast QR codes with preprocessing

**Usage:**
```
python qr_codec.py --decode <image_file>
python qr_codec.py --encode "Hello World" --output qr.png
python qr_codec.py --decode qr.png --preprocess
```

**Dependencies:** `qrcode`, `pyzbar`, `Pillow`

---

### [barcode_decoder.py](barcode_decoder.py)

**Summary:** Decodes 1D and 2D barcodes (Code128, EAN, PDF417, DataMatrix, etc.) from image files.

**Use cases:**
- Decode a barcode image provided in a CTF challenge
- Supports multiple barcode types in a single image
- Outputs decoded text and barcode type

**Usage:**
```
python barcode_decoder.py <image_file>
python barcode_decoder.py barcode.png
python barcode_decoder.py barcode.jpg --type CODE128
```

**Dependencies:** `pyzbar`, `Pillow`

---

### [esoteric_interpreter.py](esoteric_interpreter.py)

**Summary:** Interprets Brainfuck, Malbolge, and JSFuck esoteric programming languages.

**Use cases:**
- Execute Brainfuck programs commonly found in CTF encoding challenges
- Interpret obfuscated JSFuck JavaScript without a browser
- Attempt Malbolge execution for extreme obfuscation challenges

**Usage:**
```
python esoteric_interpreter.py --lang brainfuck --code "++++++++++[>+>+++>++++...]"
python esoteric_interpreter.py --lang jsfuck --code "[][(![]+[])[+[]]...]"
python esoteric_interpreter.py --lang malbolge --file program.mal
```

**Dependencies:** None (custom interpreters)

---

### [regex_extractor.py](regex_extractor.py)

**Summary:** Extracts common patterns (emails, IPs, URLs, hashes, flags) from text using regex.

**Use cases:**
- Pull all IP addresses or URLs from a large text dump
- Extract all SHA256/MD5 hashes from a log file for cracking
- Find flag-format strings across unstructured text

**Usage:**
```
python regex_extractor.py <file> [--pattern emails|ips|urls|hashes|flags|all]
python regex_extractor.py dump.txt --pattern all
python regex_extractor.py dump.txt --pattern flags --flag-format "CTF\{[^}]+\}"
```

**Dependencies:** `re`

---

### [flag_grepper.py](flag_grepper.py)

**Summary:** Recursively searches all files in a directory for CTF flag patterns.

**Use cases:**
- Run after extracting an archive or mounting a disk image to find any flags
- Configurable flag format regex (default covers common CTF formats)
- Searches binary and text files, reports file path and matching line

**Usage:**
```
python flag_grepper.py <directory> [--format REGEX]
python flag_grepper.py ./extracted/
python flag_grepper.py ./extracted/ --format "HTB\{[^}]+\}"
python flag_grepper.py ./extracted/ --binary
```

**Dependencies:** `re`, `os`

---

### [base_converter.py](base_converter.py)

**Summary:** Converts numbers between binary, octal, decimal, and hexadecimal representations.

**Use cases:**
- Quickly convert addresses or values between bases during exploit development
- Batch convert a list of values from a file
- Supports arbitrary-width zero-padding and prefix formatting

**Usage:**
```
python base_converter.py <value> [--from base] [--to base]
python base_converter.py 255 --from dec --to hex
python base_converter.py 0xff --from hex --to bin
python base_converter.py 0b11001010 --from bin --to all
```

**Dependencies:** None

---

### [cyberchef_runner.py](cyberchef_runner.py)

**Summary:** CLI wrapper for running CyberChef recipes against input data using the CyberChef Node.js API.

**Use cases:**
- Apply a saved CyberChef recipe to a file without opening a browser
- Automate multi-step decode pipelines (base64 -> XOR -> inflate)
- Batch process multiple inputs with the same recipe

**Usage:**
```
python cyberchef_runner.py --recipe recipe.json --input data.bin
python cyberchef_runner.py --recipe "From_Base64,XOR({'key':'41','xorKey':'41'})" --input encoded.txt
python cyberchef_runner.py --recipe recipe.json --input-dir ./inputs/ --output-dir ./outputs/
```

**Dependencies:** `node.js`, `cyberchef` (npm)

---

### [wordlist_generator.py](wordlist_generator.py)

**Summary:** Generates custom wordlists using mutation rules, character substitutions, and OSINT-derived terms.

**Use cases:**
- Create targeted password lists for a challenge using known names, dates, and keywords
- Apply leet-speak, capitalisation, and suffix/prefix mutations to a base wordlist
- Combine multiple word sources and deduplicate

**Usage:**
```
python wordlist_generator.py --words base.txt --rules leet,caps,years
python wordlist_generator.py --osint "John Smith,1990,London" --output john_wordlist.txt
python wordlist_generator.py --words base.txt --min-len 8 --max-len 16 --output list.txt
```

**Dependencies:** `itertools`

---

### [hash_cracker.py](hash_cracker.py)

**Summary:** Wraps hashcat and john the ripper for hash cracking with automatic mode selection.

**Use cases:**
- Crack a hash identified by hash_identifier.py using the appropriate hashcat mode
- Use john with a wordlist and rules for common CTF hash challenges
- Automatically detects hash type and selects the right attack mode

**Usage:**
```
python hash_cracker.py --hash 5f4dcc3b5aa765d61d8327deb882cf99 --wordlist rockyou.txt
python hash_cracker.py --hash-file hashes.txt --tool john --rules
python hash_cracker.py --hash <hash> --tool hashcat --mode 0 --wordlist rockyou.txt
```

**Dependencies:** `hashcat` or `john` (system)

---

### [recursive_unpacker.py](recursive_unpacker.py)

**Summary:** Recursively extracts nested archives (zip, tar, gz, bz2, 7z, rar) with optional password list support.

**Use cases:**
- Unpack a deeply nested archive challenge automatically
- Try each password from a list at every layer
- Reports the extraction tree and any passwords successfully used

**Usage:**
```
python recursive_unpacker.py <archive> [--passwords passwords.txt] [--output-dir DIR]
python recursive_unpacker.py challenge.zip --output-dir ./out/
python recursive_unpacker.py matryoshka.tar.gz --passwords rockyou.txt
```

**Dependencies:** `zipfile`, `tarfile`, `py7zr`, `rarfile`

---

### [auto_identifier.py](auto_identifier.py)

**Summary:** Automatically identifies the encoding, cipher, or file format of an unknown input string or file.

**Use cases:**
- Paste an unknown string and get a ranked list of likely encodings or ciphers
- Detects Base64, hex, Morse, binary, Caesar, hashes, magic bytes, and more
- Starting point before selecting the appropriate decode/attack tool

**Usage:**
```
python auto_identifier.py <string_or_file>
python auto_identifier.py "SGVsbG8gV29ybGQ="
python auto_identifier.py unknown_file.bin
python auto_identifier.py "... --- ..." --top 5
```

**Dependencies:** `re`, `base64`, `binascii`

---

### [flag_submitter.py](flag_submitter.py)

**Summary:** Submits CTF flags to a competition platform API with rate-limit handling and response logging.

**Use cases:**
- Automate flag submission when solving many challenges programmatically
- Handles 429 rate limiting with configurable backoff
- Logs all submission attempts and responses

**Usage:**
```
python flag_submitter.py --flag "CTF{...}" --challenge-id 42 --api-url http://ctf.example.com/api
python flag_submitter.py --flags flags.txt --api-url http://ctf.example.com/api --token $API_TOKEN
```

**Dependencies:** `requests`

---

### [challenge_timer.py](challenge_timer.py)

**Summary:** CLI challenge timer with integrated note-taking and session logging.

**Use cases:**
- Track time spent per challenge for post-competition writeup accuracy
- Take timestamped notes inline without leaving the terminal
- Export session log as a structured JSON for writeup generation

**Usage:**
```
python challenge_timer.py --start "Web Challenge 1"
python challenge_timer.py --note "Found SQLi in login param"
python challenge_timer.py --stop --export session.json
```

**Dependencies:** `datetime`, `json`

---

### [obsidian_scaffold.py](obsidian_scaffold.py)

**Summary:** Generates an Obsidian-compatible CTF writeup folder structure with pre-filled markdown templates.

**Use cases:**
- Instantly scaffold a writeup vault for a new CTF event
- Creates per-challenge notes with metadata, approach, and flag fields
- Links challenges to a central event overview note

**Usage:**
```
python obsidian_scaffold.py --event "CTF Event 2025" --output ./vault/
python obsidian_scaffold.py --event "PicoCTF" --challenges "Web 1,Crypto 1,Forensics 1"
python obsidian_scaffold.py --event "HackThisSite" --output ./vault/ --template custom.md
```

**Dependencies:** `os`, `datetime`
