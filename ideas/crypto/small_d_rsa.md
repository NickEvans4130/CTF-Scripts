# Script Ideas — Small Private Exponent RSA

Scripts that would have accelerated or improved solving this challenge.

---

## 1. RSA Parameter Analyser

**What it would do:**
Parse RSA parameters (`n`, `e`, `c`, optionally `p`, `q`, `d`) from a file or stdin and automatically identify which classical attacks apply based on the values:
- Wiener's attack — `d` small relative to `n`
- Boneh-Durfee — `d` slightly larger than Wiener's bound (requires LLL lattice reduction)
- Small `e` / Coppersmith — `e` is 3, 17, or 65537 and message is small/padded weakly
- Common modulus — same `n`, different `e`, same plaintext
- Fermat's factorisation — `p` and `q` are close together
- Low-entropy `p`/`q` — primes generated with a weak RNG

**Why it would help:**
The vulnerability here (small `d`) is immediately visible from the key sizes in `encryption.py`, but having a script that reads `message.txt`, checks bit lengths of `n` and `e`, and says "Wiener's attack likely — e is large relative to n^(3/4)" would make triage instant.

**Suggested interface:**
```bash
python3 rsa_analyser.py message.txt
# Output:
# n = 2096 bits, e = 2095 bits, c = 2095 bits
# e > n^0.75 — likely small d. Recommend: Wiener's attack.
```

---

## 2. Wiener's Attack Tool

**What it would do:**
Take `n`, `e`, `c` and run Wiener's continued-fraction attack to recover `d`, then decrypt `c`. Output `d`, the factorisation of `n`, and the decrypted plaintext.

**Why it would help:**
This is the exact attack needed. Having it as a reusable script means no re-implementing continued fractions per challenge.

**Suggested interface:**
```bash
python3 wieners_attack.py --n <n> --e <e> --c <c>
python3 wieners_attack.py --file message.txt
```

---

## 3. RSA CTF Solver (multi-attack)

**What it would do:**
A unified script that reads RSA parameters and tries multiple attacks in sequence: Wiener's, small `e` cube-root, Fermat factorisation, common modulus (if multiple ciphertexts provided), and direct factorisation via `factordb` API lookup for small/known `n`. Returns the first successful decryption.

**Why it would help:**
Removes the need to identify the specific attack manually. For challenges with a single vulnerability this is overkill, but for harder challenges with subtle parameter weaknesses it saves significant time.

**Suggested interface:**
```bash
python3 rsa_solver.py message.txt
# Trying Fermat factorisation... failed
# Trying small-e root... failed
# Trying Wiener's attack... SUCCESS
# d = 59503...
# flag: picoCTF{sm4ll_d_6ea2db76}
```
