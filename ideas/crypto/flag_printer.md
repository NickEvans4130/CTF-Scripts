# Script Ideas — flag_printer

Scripts that would have accelerated or improved solving this challenge.

---

## 1. Newton Interpolation Solver (Consecutive Integer Points)

**What it would do:**
Given evaluation pairs `(i, y_i)` for `i = 0, 1, ..., n-1` of a polynomial `p(x) mod MOD`, recover all monomial coefficients via:
1. NTT-based Newton forward differences (O(n log n))
2. D&C Newton→Monomial conversion via Taylor shifts using python-flint (O(n log² n))

**Why it would help:**
This is a clean, reusable algorithm for any challenge with consecutive-integer evaluation points. The key ideas — Newton differences as a convolution, and D&C reconstruction — are non-obvious but widely applicable. Having a working reference would save significant implementation and debugging time.

**Suggested interface:**
```bash
python3 newton_interpolate.py \
    --input encoded.txt \   # "x y" lines
    --mod 7514777789 \
    --output output.bmp
```

**Implementation notes:**
- Use 3-prime NTT (Q1=998244353, Q2=985661441, Q3=469762049) + CRT for the convolution
- **Critical:** compute `A[i] = y[i] * inv_fact[i] % MOD` using Python integers, not numpy int64, when `MOD > 3e9` (products can overflow int64)
- D&C base case threshold ~64; use `nmod_poly.compose()` from python-flint for Taylor shifts
- Set `sys.setrecursionlimit` appropriately for large n

---

## 2. numpy int64 Overflow Detector

**What it would do:**
Given a numpy array operation and a modulus, detect whether the intermediate products can overflow int64. Report the maximum possible product and whether it exceeds `2^63 - 1`. Suggest using `object` dtype or Python-level computation instead.

**Why it would help:**
The most time-consuming bug in this challenge was a silent int64 overflow in `y * inv_fact % MOD`. When `MOD > sqrt(int64_max) ≈ 3.03e9`, multiplying two residues overflows. This is easy to miss and produces wrong answers with no error. A quick check would catch it immediately.

**Suggested interface:**
```python
from overflow_check import check_modmul
check_modmul(MOD=7514777789)
# Output:
# Max product: 5.64e19
# int64_max:   9.22e18
# OVERFLOW: use Python ints or split multiplication
```

---

## 3. NTT Prime Selector

**What it would do:**
Given a required transform size `n` and a desired total modulus `M`, find suitable NTT-friendly primes of the form `k * 2^r + 1` where `2^r >= n`. Output a set of primes whose product exceeds `M * n` (ensuring no CRT ambiguity after convolution).

**Why it would help:**
Choosing NTT primes is mechanical but error-prone. This tool would instantly give usable primes for any problem size and modulus, removing the need to look up or pre-verify primes.

**Suggested interface:**
```bash
python3 ntt_prime_selector.py --n 4000000 --mod 7514777789
# Output:
# Selected primes: [998244353, 985661441, 469762049]
# Product: 4.62e26 > max_coeff * n = 2.81e22 ✓
# All support NTT for n up to 2^23 ✓
```
