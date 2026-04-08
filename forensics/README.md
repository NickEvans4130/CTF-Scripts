# Forensics

Scripts for file analysis, data recovery, and artifact extraction.

---

## Scripts

### [png_jpeg_metadata_extractor.py](png_jpeg_metadata_extractor.py)

**Summary:** Wraps `exiftool` to extract and display all metadata from PNG and JPEG files.

**Use cases:**
- Recover GPS coordinates, camera model, timestamps embedded in challenge images
- Find hidden comments or software fields that hint at steganography tools used
- Compare original vs modified EXIF to detect tampering

**Usage:**
```
python png_jpeg_metadata_extractor.py <image_file>
python png_jpeg_metadata_extractor.py image.jpg
python png_jpeg_metadata_extractor.py image.png --json
```

**Dependencies:** `exiftool` (system), `subprocess`

---

### [steganography_detector.py](steganography_detector.py)

**Summary:** Detects hidden data in images using LSB analysis and chi-square statistical tests.

**Use cases:**
- Determine if an image likely contains hidden payload before attempting extraction
- Chi-square test flags statistically non-random LSBs that indicate steganography
- Supports PNG, BMP, and lossless formats where LSB steg is viable

**Usage:**
```
python steganography_detector.py <image_file>
python steganography_detector.py suspicious.png --chi-square
python steganography_detector.py suspicious.png --lsb-visualise
```

**Dependencies:** `Pillow`, `numpy`, `scipy`

---

### [lsb_extractor.py](lsb_extractor.py)

**Summary:** Extracts LSB-encoded hidden data from images and audio files.

**Use cases:**
- Extract flags or files hidden in the least significant bits of image pixels
- Supports RGB channel selection (R, G, B, or all) and bit-plane selection
- Audio LSB extraction from WAV sample data

**Usage:**
```
python lsb_extractor.py image <image_file> [--channel R|G|B|all] [--bits 1-8]
python lsb_extractor.py audio <wav_file>
python lsb_extractor.py image steg.png --channel B --bits 2 --output out.bin
```

**Dependencies:** `Pillow`, `numpy`, `wave`

---

### [binwalk_wrapper.py](binwalk_wrapper.py)

**Summary:** Wraps `binwalk` for signature scanning and performs recursive file carving on extracted results.

**Use cases:**
- Identify and extract embedded files (ZIP, PE, ELF, filesystem images) within a binary blob
- Recursive mode re-runs binwalk on every extracted file until no new files are found
- Useful for firmware images and challenge files that layer multiple containers

**Usage:**
```
python binwalk_wrapper.py <file> [--recursive] [--depth N]
python binwalk_wrapper.py firmware.bin --recursive --depth 5
python binwalk_wrapper.py challenge.jpg --output ./extracted/
```

**Dependencies:** `binwalk` (system)

---

### [zip_rar_bruteforcer.py](zip_rar_bruteforcer.py)

**Summary:** Brute-forces password-protected ZIP and RAR archives using a wordlist or charset-based generation.

**Use cases:**
- Crack common CTF passwords (rockyou, custom wordlists)
- Charset mode for short unknown passwords (digits, lowercase, mixed)
- Supports multi-threaded attempts for speed

**Usage:**
```
python zip_rar_bruteforcer.py <archive> --wordlist <wordlist>
python zip_rar_bruteforcer.py secret.zip --wordlist /usr/share/wordlists/rockyou.txt
python zip_rar_bruteforcer.py secret.zip --charset digits --max-len 6
python zip_rar_bruteforcer.py secret.rar --wordlist rockyou.txt --threads 8
```

**Dependencies:** `zipfile`, `rarfile`, `itertools`, `threading`

---

### [nested_archive_extractor.py](nested_archive_extractor.py)

**Summary:** Recursively extracts nested archives (zip, tar, gz, bz2, 7z, rar), trying password lists at each layer.

**Use cases:**
- CTF challenges that nest dozens of archives as a stalling mechanic
- Automatically tries each password from a provided list at every layer
- Handles mixed format nesting (zip inside tar inside gz, etc.)

**Usage:**
```
python nested_archive_extractor.py <archive> [--passwords passwords.txt]
python nested_archive_extractor.py challenge.zip --passwords pass.txt --output ./out/
python nested_archive_extractor.py matryoshka.tar.gz
```

**Dependencies:** `zipfile`, `tarfile`, `rarfile`, `py7zr`

---

### [pcap_analyser.py](pcap_analyser.py)

**Summary:** Parses PCAP files to extract HTTP requests/responses, DNS queries, and raw TCP streams.

**Use cases:**
- Reconstruct HTTP conversations to find submitted flags or credentials
- Extract DNS query names that spell out encoded data
- Reassemble TCP streams and dump them as files or text

**Usage:**
```
python pcap_analyser.py <pcap_file> [--mode http|dns|tcp|all]
python pcap_analyser.py capture.pcap --mode http
python pcap_analyser.py capture.pcap --mode dns --output dns_queries.txt
python pcap_analyser.py capture.pcap --mode tcp --stream 3
```

**Dependencies:** `scapy` or `pyshark`

---

### [hid_mouse_decoder.py](hid_mouse_decoder.py)

**Summary:** Decodes USB HID mouse reports from PCAP data, reconstructing relative X/Y movement into a cursor path.

**Use cases:**
- CTF challenges that encode a flag as mouse movements captured in a USB traffic PCAP
- Renders the reconstructed path as a matplotlib image to visually read text/patterns
- Handles standard 3-byte and 4-byte HID mouse report formats

**Usage:**
```
python hid_mouse_decoder.py <pcap_file> [--output path.png]
python hid_mouse_decoder.py usb_capture.pcap
python hid_mouse_decoder.py usb_capture.pcap --output cursor_path.png --scale 2
```

**Dependencies:** `scapy`, `matplotlib`

---

### [memory_dump_extractor.py](memory_dump_extractor.py)

**Summary:** Extracts printable strings from memory dumps and greps for patterns like flags, URLs, and credentials.

**Use cases:**
- Search a raw memory dump for flag formats (`CTF{...}`, `flag{...}`)
- Extract URLs, email addresses, and credential patterns
- Filter by minimum string length to reduce noise

**Usage:**
```
python memory_dump_extractor.py <dump_file> [--pattern PATTERN] [--min-len N]
python memory_dump_extractor.py memory.dmp --pattern "flag{"
python memory_dump_extractor.py memory.dmp --min-len 8 --output strings.txt
```

**Dependencies:** `re`, `struct`

---

### [disk_image_walker.py](disk_image_walker.py)

**Summary:** Mounts or parses a disk image and walks the file system, listing and optionally extracting files.

**Use cases:**
- Browse files inside a raw disk image (.img, .dd) without manual mounting
- Extract specific files or all files matching a pattern
- Supports FAT32, ext2/3/4 via `pytsk3` or `libguestfs`

**Usage:**
```
python disk_image_walker.py <image_file> [--extract PATH] [--list]
python disk_image_walker.py disk.img --list
python disk_image_walker.py disk.img --extract /home/user/.bash_history
```

**Dependencies:** `pytsk3` or `libguestfs` (system)

---

### [magic_byte_identifier.py](magic_byte_identifier.py)

**Summary:** Identifies file type from magic bytes and optionally fixes the header if it has been tampered with.

**Use cases:**
- Identify a file with a wrong or stripped extension
- Detect and fix corrupted/swapped magic bytes (common in CTF file challenges)
- Lists known magic bytes for common formats and suggests fixes

**Usage:**
```
python magic_byte_identifier.py <file>
python magic_byte_identifier.py unknown_file
python magic_byte_identifier.py broken.png --fix --expected png
```

**Dependencies:** `python-magic`

---

### [deleted_file_recovery.py](deleted_file_recovery.py)

**Summary:** Attempts to recover deleted files from raw disk images by scanning for file signatures.

**Use cases:**
- Recover a deleted flag file from a provided disk image
- Carves files based on known header/footer signatures (JPEG, PNG, PDF, ZIP, etc.)
- Works on raw images without a filesystem; useful when directory entries are wiped

**Usage:**
```
python deleted_file_recovery.py <image_file> [--output-dir DIR]
python deleted_file_recovery.py disk.img --output-dir ./recovered/
python deleted_file_recovery.py disk.img --types jpeg,png,zip
```

**Dependencies:** `struct`, `os`

---

### [audio_spectrogram_visualiser.py](audio_spectrogram_visualiser.py)

**Summary:** Generates spectrograms from audio files to reveal hidden text, Morse code, or DTMF tones.

**Use cases:**
- Visualise a spectrogram where a flag is written in frequency space
- Detect DTMF tones and decode them to digits
- Detect Morse code patterns in an audio channel

**Usage:**
```
python audio_spectrogram_visualiser.py <audio_file> [--mode spectrogram|dtmf|morse]
python audio_spectrogram_visualiser.py hidden.wav --mode spectrogram --output spec.png
python audio_spectrogram_visualiser.py tones.wav --mode dtmf
```

**Dependencies:** `scipy`, `numpy`, `matplotlib`, `librosa`

---

### [wav_mp3_lsb_extractor.py](wav_mp3_lsb_extractor.py)

**Summary:** Extracts data hidden in the LSBs of WAV sample values or MP3 frame padding.

**Use cases:**
- Extract a payload hidden in WAV audio samples using steghide or manual LSB embedding
- Check MP3 ID3 tags and frame ancillary data for hidden content
- Supports stereo channel selection and bit-depth options

**Usage:**
```
python wav_mp3_lsb_extractor.py <audio_file> [--channel left|right|both] [--bits N]
python wav_mp3_lsb_extractor.py audio.wav --channel left --bits 1
python wav_mp3_lsb_extractor.py audio.mp3 --output extracted.bin
```

**Dependencies:** `wave`, `mutagen`, `numpy`

---

### [pdf_extractor.py](pdf_extractor.py)

**Summary:** Extracts hidden layers, annotations, attachments, and metadata from PDF files.

**Use cases:**
- Find text hidden behind white boxes or in invisible layers
- Extract embedded file attachments and JavaScript
- Dump XMP/DocInfo metadata fields that may contain hints

**Usage:**
```
python pdf_extractor.py <pdf_file> [--layers] [--attachments] [--metadata]
python pdf_extractor.py challenge.pdf --layers --output layers/
python pdf_extractor.py challenge.pdf --attachments
```

**Dependencies:** `PyMuPDF` (fitz), `pdfminer`

---

### [office_doc_extractor.py](office_doc_extractor.py)

**Summary:** Extracts macros, metadata, and hidden content from Office documents (DOCX, XLSX, PPTX, DOC, XLS).

**Use cases:**
- Extract VBA macros that may contain encoded flags or credentials
- Dump document metadata (author, last modified by, revision history)
- Unzip OOXML files and inspect embedded XML for hidden data

**Usage:**
```
python office_doc_extractor.py <office_file> [--macros] [--metadata] [--unzip]
python office_doc_extractor.py document.docx --macros
python office_doc_extractor.py spreadsheet.xlsx --metadata --unzip ./extracted/
```

**Dependencies:** `python-docx`, `openpyxl`, `oletools`

---

### [timestamps_analyser.py](timestamps_analyser.py)

**Summary:** Analyses and compares file system timestamps from NTFS MFT records or ext4 inodes.

**Use cases:**
- Detect timestamp manipulation (anti-forensics) by comparing $STANDARD_INFORMATION vs $FILE_NAME
- Build a timeline of file access/modification events from a disk image
- Export timestamps in human-readable and CSV formats for investigation

**Usage:**
```
python timestamps_analyser.py <image_or_file> [--format ntfs|ext4] [--timeline]
python timestamps_analyser.py disk.img --format ntfs --timeline
python timestamps_analyser.py disk.img --format ext4 --output timeline.csv
```

**Dependencies:** `pytsk3`, `datetime`

---

### [eml_mime_parser.py](eml_mime_parser.py)

**Summary:** Parses EML and MIME email files, extracting headers, body text, and attachments.

**Use cases:**
- Extract attachments from a suspicious email file provided in a challenge
- Decode base64 or quoted-printable encoded email bodies
- Trace email routing via Received headers

**Usage:**
```
python eml_mime_parser.py <eml_file> [--attachments] [--headers] [--body]
python eml_mime_parser.py email.eml --attachments --output ./attachments/
python eml_mime_parser.py email.eml --headers
```

**Dependencies:** `email`, `mailparser`

---

### [png_ihdr_crc_bruteforcer.py](png_ihdr_crc_bruteforcer.py)

**Summary:** Brute-forces the correct width and height of a PNG with a corrupted IHDR chunk by searching for a valid CRC32 match.

**Use cases:**
- Fix a PNG whose dimensions were deliberately zeroed or altered to prevent rendering
- Searches a configurable range of width/height pairs simultaneously
- Outputs the corrected PNG once a matching CRC32 is found

**Usage:**
```
python png_ihdr_crc_bruteforcer.py <png_file> [--max-dim N]
python png_ihdr_crc_bruteforcer.py broken.png
python png_ihdr_crc_bruteforcer.py broken.png --max-dim 4096 --output fixed.png
```

**Dependencies:** `struct`, `zlib`
