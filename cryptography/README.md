# Cryptography

Scripts for attacking classical and modern ciphers, RSA, AES, and hash constructions.

---

## Scripts

### [caesar_rot_bruteforcer.py](caesar_rot_bruteforcer.py)

**Summary:** Brute-forces all 25 Caesar / ROT-N shifts and scores each candidate using English letter frequency analysis.

**Use cases:**
- Instantly solve ROT13 or arbitrary Caesar-shifted CTF ciphertext
- Frequency scoring ranks the most likely plaintexts at the top
- Handles uppercase, lowercase, and ignores non-alpha characters

**Usage:**
```
python caesar_rot_bruteforcer.py <ciphertext>
python caesar_rot_bruteforcer.py "Uryyb Jbeyq"
python caesar_rot_bruteforcer.py --file cipher.txt --top 5
```

**Dependencies:** `string`, `collections`

---

### [vigenere_cracker.py](vigenere_cracker.py)

**Summary:** Cracks Vigenère ciphers by estimating key length via Index of Coincidence (IC) and then recovering each key byte via frequency analysis.

**Use cases:**
- Recover the key and plaintext from a Vigenère-encrypted CTF challenge
- IC analysis works well for key lengths up to ~20 characters
- Outputs the most likely key and decrypted plaintext

**Usage:**
```
python vigenere_cracker.py <ciphertext>
python vigenere_cracker.py --file cipher.txt
python vigenere_cracker.py --file cipher.txt --max-keylen 30 --top 3
```

**Dependencies:** `string`, `collections`

---

### [xor_bruteforcer.py](xor_bruteforcer.py)

**Summary:** Brute-forces single-byte and multi-byte XOR keys against ciphertext using frequency analysis scoring.

**Use cases:**
- Crack single-byte XOR ciphertext (classic CTF encoding)
- Multi-byte mode uses Kasiski / Hamming distance to find key length, then solves each byte
- Scores results by English plaintext likelihood

**Usage:**
```
python xor_bruteforcer.py --hex <hex_ciphertext> [--keylen N]
python xor_bruteforcer.py --hex deadbeef01020304 --single
python xor_bruteforcer.py --file cipher.bin --keylen 8
python xor_bruteforcer.py --file cipher.bin --max-keylen 20
```

**Dependencies:** `binascii`, `itertools`

---

### [xor_known_plaintext.py](xor_known_plaintext.py)

**Summary:** Recovers an XOR key when a portion of the plaintext is known (known-plaintext attack).

**Use cases:**
- Recover key bytes by XORing known plaintext against ciphertext at the same offset
- Extend partial key recovery to full key using crib-dragging
- Useful when flag format (`CTF{`) is known and message is XOR-encrypted

**Usage:**
```
python xor_known_plaintext.py --cipher <hex> --known <plaintext> [--offset N]
python xor_known_plaintext.py --cipher 1a2b3c4d --known "CTF{" --offset 0
python xor_known_plaintext.py --file cipher.bin --known "flag{" --crib-drag
```

**Dependencies:** `binascii`

---

### [transposition_bruteforcer.py](transposition_bruteforcer.py)

**Summary:** Brute-forces rail fence and columnar transposition ciphers.

**Use cases:**
- Try all rail counts for rail fence cipher
- Try key lengths and column orderings for columnar transposition
- Scores candidates with frequency analysis to surface likely plaintexts

**Usage:**
```
python transposition_bruteforcer.py --mode rail <ciphertext>
python transposition_bruteforcer.py --mode columnar <ciphertext> --max-cols 12
python transposition_bruteforcer.py --mode rail "WecrlteerdsoeefeaaboraottFamc"
```

**Dependencies:** `itertools`, `string`

---

### [base_autodetector.py](base_autodetector.py)

**Summary:** Automatically detects and decodes Base16, Base32, Base58, Base62, Base64, and Base85 encoded strings.

**Use cases:**
- Quickly decode an unknown-encoding CTF string without guessing format
- Tries all supported bases and outputs valid decode candidates
- Handles padded and unpadded variants

**Usage:**
```
python base_autodetector.py <encoded_string>
python base_autodetector.py "SGVsbG8gV29ybGQ="
python base_autodetector.py --file encoded.txt
```

**Dependencies:** `base64`, `base58` (pip)

---

### [base64_repeated_decode.py](base64_repeated_decode.py)

**Summary:** Repeatedly Base64-decodes a string until no further valid decoding is possible.

**Use cases:**
- CTF challenges that nest multiple layers of Base64 encoding
- Stops when output is no longer valid Base64 or a flag is detected
- Prints each intermediate step

**Usage:**
```
python base64_repeated_decode.py <encoded_string>
python base64_repeated_decode.py "Vm0wd2QyUXlVWGxWV0d4V1YwZDRWMVl3Wkc5alJsWjBUVlpPV0ZKc2JETlhhMUpUVmpBeFYy..."
```

**Dependencies:** `base64`

---

### [rsa_factor.py](rsa_factor.py)

**Summary:** Attempts to factor RSA modulus N using trial division (small primes), Fermat's factorisation, and Pollard's rho algorithm.

**Use cases:**
- Factor weak RSA moduli common in CTF challenges
- Fermat works when p and q are close together
- Pollard's rho handles larger smooth factors

**Usage:**
```
python rsa_factor.py --n <N> [--e <e>] [--c <ciphertext>]
python rsa_factor.py --n 3233 --e 17 --c 2790
python rsa_factor.py --n <large_N> --e 65537 --c <ct> --method pollard
```

**Dependencies:** `sympy`, `gmpy2`

---

### [rsa_common_modulus.py](rsa_common_modulus.py)

**Summary:** Recovers RSA plaintext when the same message is encrypted with two different exponents sharing the same modulus.

**Use cases:**
- Attack scenarios where a server signs with two keys that share N
- Applies extended Euclidean algorithm to recover plaintext without factoring N
- Requires gcd(e1, e2) == 1

**Usage:**
```
python rsa_common_modulus.py --n <N> --e1 <e1> --c1 <c1> --e2 <e2> --c2 <c2>
```

**Dependencies:** `gmpy2`

---

### [rsa_wiener.py](rsa_wiener.py)

**Summary:** Implements Wiener's continued fraction attack to recover a small private exponent d.

**Use cases:**
- Attack RSA when d < N^(1/4) (Wiener's bound)
- CTF challenges that use a very small d for "efficiency"
- Returns d directly, allowing decryption of any ciphertext

**Usage:**
```
python rsa_wiener.py --n <N> --e <e>
python rsa_wiener.py --n <N> --e <e> --c <ciphertext>
```

**Dependencies:** `gmpy2`

---

### [rsa_hastad.py](rsa_hastad.py)

**Summary:** Implements Håstad's broadcast attack to recover a plaintext encrypted with a low exponent (e=3) to multiple recipients.

**Use cases:**
- Attack RSA with e=3 and 3 different moduli using Chinese Remainder Theorem
- Generalised to arbitrary low e with e ciphertexts
- Requires e (n, c) pairs

**Usage:**
```
python rsa_hastad.py --e 3 --pairs "n1,c1" "n2,c2" "n3,c3"
python rsa_hastad.py --e 3 --file pairs.txt
```

**Dependencies:** `gmpy2`, `sympy`

---

### [rsa_crt_fault.py](rsa_crt_fault.py)

**Summary:** Recovers RSA private key using the CRT fault attack when two signatures are available — one correct and one faulty.

**Use cases:**
- Exploit a faulty RSA-CRT implementation that produced a bad signature
- Recovers p and q from gcd(s_faulty - s_correct, N)
- One bad signature is sufficient to factor N

**Usage:**
```
python rsa_crt_fault.py --n <N> --e <e> --m <message> --s-good <s1> --s-bad <s2>
```

**Dependencies:** `gmpy2`

---

### [rsa_partial_key.py](rsa_partial_key.py)

**Summary:** Reconstructs full RSA private key from partial known bits of d or p.

**Use cases:**
- Coppersmith-style attack when lower bits of d are known
- Useful when a memory leak or side-channel reveals partial key material
- Implements lattice-based recovery

**Usage:**
```
python rsa_partial_key.py --n <N> --e <e> --d-partial <bits> --known-lsb <k>
```

**Dependencies:** `gmpy2`, `sage` (optional for lattice methods)

---

### [hash_length_extension.py](hash_length_extension.py)

**Summary:** Performs length extension attacks against SHA-1, MD5, and SHA-256 MACs.

**Use cases:**
- Forge a MAC for an extended message when the original MAC and message length are known
- SHA-1 and MD5 are vulnerable; SHA-256 is included for completeness
- Outputs forged message and MAC ready to submit

**Usage:**
```
python hash_length_extension.py --algo sha1 --mac <mac> --msg <known_msg> --append <data> --secret-len N
```

**Dependencies:** `hlextend` or custom implementation

---

### [sha1_length_extension.py](sha1_length_extension.py)

**Summary:** Reusable SHA-1 length extension module exposing padding calculation, forged message construction, and MAC output.

**Use cases:**
- Import as a library in exploit scripts that need SHA-1 length extension
- Calculates exact padding bytes for any message length and secret length
- Returns both the forged message (with padding) and the new MAC

**Usage:**
```python
from sha1_length_extension import extend
forged_msg, forged_mac = extend(original_mac, original_msg_len, secret_len, append_data)
```

**Dependencies:** `struct`

---

### [aes_cbc_bitflip.py](aes_cbc_bitflip.py)

**Summary:** Demonstrates and automates AES-CBC bit-flipping attacks to modify decrypted plaintext bytes.

**Use cases:**
- Flip specific bits in a CBC ciphertext to produce a chosen plaintext after decryption
- Bypass `admin=true` checks that rely on CBC-decrypted user-controlled data
- Interactive mode lets you specify target byte position and desired value

**Usage:**
```
python aes_cbc_bitflip.py --ciphertext <hex> --block-size 16 --target-offset N --desired-byte 0x3b
```

**Dependencies:** `pycryptodome`

---

### [aes_cbc_padding_oracle.py](aes_cbc_padding_oracle.py)

**Summary:** Automates the CBC padding oracle attack to decrypt arbitrary ciphertext block-by-block.

**Use cases:**
- Decrypt a CBC-mode ciphertext using only a padding oracle (valid/invalid response)
- Works against web endpoints or local oracle functions
- Recovers full plaintext one byte at a time

**Usage:**
```
python aes_cbc_padding_oracle.py --ciphertext <hex> --iv <hex> --oracle-url <url>
python aes_cbc_padding_oracle.py --ciphertext <hex> --oracle-script oracle.py
```

**Dependencies:** `pycryptodome`, `requests`

---

### [aes_ecb_byte_at_a_time.py](aes_ecb_byte_at_a_time.py)

**Summary:** Performs the ECB byte-at-a-time decryption attack against an oracle that appends a secret before encrypting.

**Use cases:**
- Recover the appended secret from an ECB oracle one byte at a time
- Determines block size automatically
- Works on both prefix and suffix secrets

**Usage:**
```
python aes_ecb_byte_at_a_time.py --oracle-script oracle.py
python aes_ecb_byte_at_a_time.py --oracle-url http://target/encrypt
```

**Dependencies:** `pycryptodome`, `requests`

---

### [aes_ecb_block_boundaries.py](aes_ecb_block_boundaries.py)

**Summary:** Detects AES-ECB mode and identifies block boundaries by finding repeated blocks in oracle output.

**Use cases:**
- Confirm ECB mode is in use before attempting byte-at-a-time attack
- Determine block size and prefix length for crafted payloads
- Visual block boundary map output

**Usage:**
```
python aes_ecb_block_boundaries.py --oracle-script oracle.py
python aes_ecb_block_boundaries.py --oracle-url http://target/encrypt
```

**Dependencies:** `pycryptodome`, `requests`

---

### [aes_ctr_keystream_recovery.py](aes_ctr_keystream_recovery.py)

**Summary:** Recovers AES-CTR keystream when a nonce is reused across multiple ciphertexts.

**Use cases:**
- Attack a system that reuses (nonce, key) pairs across multiple encryptions
- Uses statistical XOR methods (crib-dragging) to recover keystream bytes
- Decrypts all messages once keystream is known

**Usage:**
```
python aes_ctr_keystream_recovery.py --ciphertexts file.txt [--crib "the "]
python aes_ctr_keystream_recovery.py --hex-list "ct1,ct2,ct3" --interactive
```

**Dependencies:** `binascii`

---

### [stream_cipher_oracle.py](stream_cipher_oracle.py)

**Summary:** Generic tool for keystream recovery via known plaintext XOR, with reused-nonce detection.

**Use cases:**
- Recover keystream bytes from any stream cipher when plaintext is partially known
- Detect nonce/key reuse by comparing ciphertext XOR pairs for language-like patterns
- Works as a crib-dragging interactive tool for multi-message keystream recovery

**Usage:**
```
python stream_cipher_oracle.py --mode recover --ciphertext <hex> --known <plaintext>
python stream_cipher_oracle.py --mode crib-drag --ciphertexts file.txt
python stream_cipher_oracle.py --mode detect-reuse --ciphertexts file.txt
```

**Dependencies:** `binascii`

---

### [dh_small_subgroup.py](dh_small_subgroup.py)

**Summary:** Implements the Diffie-Hellman small subgroup attack to recover a secret key modulo small factors.

**Use cases:**
- Attack DH implementations that don't validate the public key's group membership
- Recovers bits of the secret using CRT after queries with small-order elements
- Classic attack against DH over multiplicative groups with smooth (p-1)

**Usage:**
```
python dh_small_subgroup.py --p <prime> --g <generator> --public-key <A> --oracle-url <url>
```

**Dependencies:** `gmpy2`, `sympy`

---

### [discrete_log_bruteforcer.py](discrete_log_bruteforcer.py)

**Summary:** Computes discrete logarithms in small groups using baby-step giant-step (BSGS) or brute force.

**Use cases:**
- Solve g^x ≡ h (mod p) for small p or small x
- BSGS is efficient for groups up to ~2^40
- Used in DH or ElGamal challenges with weak parameters

**Usage:**
```
python discrete_log_bruteforcer.py --g <g> --h <h> --p <p> [--method bsgs|bruteforce]
```

**Dependencies:** `gmpy2`

---

### [lfsr_recovery.py](lfsr_recovery.py)

**Summary:** Recovers the initial state and feedback polynomial of an LFSR from observed output bits.

**Use cases:**
- Reverse a stream cipher based on a known or guessed LFSR length
- Berlekamp-Massey algorithm recovers the minimal polynomial from output sequence
- Predicts future LFSR output to decrypt ciphertext

**Usage:**
```
python lfsr_recovery.py --bits <binary_output_stream> [--degree N]
python lfsr_recovery.py --bits 0110100110110 --predict 64
```

**Dependencies:** `numpy`

---

### [crc_bruteforcer.py](crc_bruteforcer.py)

**Summary:** Brute-forces preimages for CRC32 and Adler32 checksums over a given charset and length.

**Use cases:**
- Find a short string that produces a target CRC32 (used in some CTF challenges)
- Verify integrity fields or forge CRC-protected messages
- Configurable charset and length range

**Usage:**
```
python crc_bruteforcer.py --algo crc32 --target 0xdeadbeef --max-len 6
python crc_bruteforcer.py --algo adler32 --target 0x1234 --charset alphanum
```

**Dependencies:** `zlib`, `itertools`

---

### [affine_bruteforcer.py](affine_bruteforcer.py)

**Summary:** Brute-forces all valid affine cipher key pairs (a, b) over a 26-character alphabet.

**Use cases:**
- Crack affine ciphers (E(x) = ax + b mod 26) by trying all valid 312 key pairs
- Scores each candidate using frequency analysis
- Handles arbitrary alphabet sizes

**Usage:**
```
python affine_bruteforcer.py <ciphertext>
python affine_bruteforcer.py "Ckkj Rbnkz" --top 5
```

**Dependencies:** `math`, `string`

---

### [substitution_solver.py](substitution_solver.py)

**Summary:** Solves monoalphabetic substitution ciphers using letter frequency analysis and bigram scoring.

**Use cases:**
- Crack substitution cipher CTF challenges automatically or interactively
- Simulated annealing search for best key mapping
- Interactive mode lets you manually fix mappings and re-score

**Usage:**
```
python substitution_solver.py <ciphertext>
python substitution_solver.py --file cipher.txt --interactive
python substitution_solver.py --file cipher.txt --iterations 10000
```

**Dependencies:** `math`, `random`

---

### [morse_codec.py](morse_codec.py)

**Summary:** Encodes and decodes Morse code, supporting standard ITU and common CTF variations.

**Use cases:**
- Decode Morse code output from audio or text challenges
- Encode plaintext to Morse for comparison or crafting
- Handles `./- ` and `*/-` delimiter variants

**Usage:**
```
python morse_codec.py --decode "... --- ..."
python morse_codec.py --encode "SOS"
python morse_codec.py --decode --delim "/" ".../.-./.../.-."
```

**Dependencies:** None

---

### [bacon_codec.py](bacon_codec.py)

**Summary:** Encodes and decodes Baconian cipher (A/B alphabet encoding of letters).

**Use cases:**
- Decode Bacon cipher where two fonts, cases, or symbols represent A and B groups
- Encode messages for CTF challenge creation or verification
- Handles both 24-letter and 26-letter variants

**Usage:**
```
python bacon_codec.py --decode "AABAA AABAB AABBA"
python bacon_codec.py --encode "HELLO"
python bacon_codec.py --decode --symbols "01" "01000 00101 01100 01100 01111"
```

**Dependencies:** None

---

### [classical_ciphers.py](classical_ciphers.py)

**Summary:** Collection of Atbash, Playfair, Beaufort, and Porta cipher encode/decode tools.

**Use cases:**
- Atbash: reverse-alphabet substitution
- Playfair: digraph substitution with a 5x5 key square
- Beaufort: reciprocal Vigenère variant
- Porta: tableau-based polyalphabetic cipher

**Usage:**
```
python classical_ciphers.py --cipher atbash --decode "ZGGZXP"
python classical_ciphers.py --cipher playfair --key "KEYWORD" --decode "CIPHERTEXT"
python classical_ciphers.py --cipher beaufort --key "KEY" --decode "CIPHERTEXT"
python classical_ciphers.py --cipher porta --key "KEY" --decode "CIPHERTEXT"
```

**Dependencies:** `string`

---

### [jwt_attacker.py](jwt_attacker.py)

**Summary:** Tests JWT tokens for the none-algorithm vulnerability, HS256 secret brute-force, and algorithm confusion (RS256 -> HS256).

**Use cases:**
- Forge JWT with `alg: none` to bypass signature verification
- Brute-force weak HS256 secrets using a wordlist
- Key confusion attack: sign with RS256 public key as HS256 secret

**Usage:**
```
python jwt_attacker.py --token <jwt> --mode none
python jwt_attacker.py --token <jwt> --mode bruteforce --wordlist rockyou.txt
python jwt_attacker.py --token <jwt> --mode confusion --pubkey public.pem
```

**Dependencies:** `PyJWT`, `cryptography`

---

### [hash_identifier.py](hash_identifier.py)

**Summary:** Identifies the likely hash algorithm from a hash string based on length and character set.

**Use cases:**
- Quickly identify an unknown hash (MD5, SHA-1, SHA-256, bcrypt, NTLM, etc.)
- Lists all plausible algorithms ranked by confidence
- Useful before passing a hash to hashcat or john

**Usage:**
```
python hash_identifier.py <hash_string>
python hash_identifier.py 5f4dcc3b5aa765d61d8327deb882cf99
```

**Dependencies:** `re`

---

### [rainbow_table_lookup.py](rainbow_table_lookup.py)

**Summary:** Looks up hashes against local or online (hashes.com, crackstation) hash databases.

**Use cases:**
- Instantly crack common MD5/SHA-1 hashes seen in CTF challenges
- Batch lookup from a file of hashes
- Falls back to local hash:plaintext CSV files if offline

**Usage:**
```
python rainbow_table_lookup.py <hash>
python rainbow_table_lookup.py --file hashes.txt
python rainbow_table_lookup.py <hash> --local-db ./rainbow.csv
```

**Dependencies:** `requests`, `hashlib`
