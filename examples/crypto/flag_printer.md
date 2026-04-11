# flag_printer

**Category:** Crypto  
**Flag:** `picoctf{i_do_hope_you_used_the_favorite_algorithm_of_every_engineering_student}`

## Challenge

Given `encoded.txt` with 1,769,611 evaluation points `(x, y)` where `y = p(x) mod MOD` (MOD = 7514777789), and `flag_printer.py` which naively solves a 1.77M × 1.77M Vandermonde system via `galois.GF`. The output is a BMP file whose bytes are the monomial coefficients of `p`.

The naive approach is computationally infeasible — O(n³) or even O(n²) is far too slow for n ≈ 1.77M.

## Solution

The evaluation points are consecutive integers `x = 0, 1, 2, ..., n-1`, which enables Newton forward differences. For a polynomial sampled at integer points, the Newton coefficients satisfy:

```
a_k = Δ^k[y](0) / k!
```

This is equivalent to a convolution:

```
a_k = conv(A, B)[k]  mod MOD
  A[j] = y[j] / j!   mod MOD
  B[m] = (-1)^m / m! mod MOD
```

### Step 1 — Newton coefficients via NTT (O(n log n))

Compute the convolution using 3-prime NTT (primes Q1=998244353, Q2=985661441, Q3=469762049 all support NTT) and reconstruct via CRT.

**Critical bug to avoid:** `y[i]` and `inv_fact[i]` are both up to ~7.5e9. Their product overflows `int64` (~9.22e18). Compute `A` using Python integers:

```python
A = np.array([int(y[i]) * inv_fact[i] % MOD for i in range(n)], dtype=np.int64)
```

### Step 2 — Newton → Monomial via D&C Taylor shift (O(n log² n))

Given Newton coefficients `a_0, ..., a_{n-1}`, recover `p(x) = sum_k a_k * x^(k)` (falling factorials → monomials) via divide-and-conquer:

- Split at midpoint `m = n//2`
- Recurse left: compute `(p_left, fall_left)` for `a[0..m-1]`
- Recurse right: compute `(q, fall_right)` for `a[m..n-1]` (relative to 0)
- Combine: `p = p_left + fall_left * q(x - m)`, `fall = fall_left * fall_right(x - m)`

The Taylor shift `q(x - m)` is polynomial composition with `(x - m)`, computed efficiently by python-flint's `nmod_poly.compose()`.

### Step 3 — Output

Write the monomial coefficients `[c_0, c_1, ..., c_{n-2}]` as bytes → BMP image.

```
First 4 bytes: [66, 77, 138, 0] = "BM..." — valid BMP header
Image: 1024 x 576 RGB
```

## Runtime

| Step | Time |
|------|------|
| Load | 0.8s |
| NTT (3 primes) | 20s |
| CRT | 0.1s |
| D&C Newton→Mono | 26s |
| **Total** | **~49s** |

## Solver

```python
"""
Flag printer challenge solver.
Step 1: Newton coefficients via NTT convolution (O(n log n))
Step 2: Newton->Monomial via D&C Taylor shift using python-flint (O(n log^2 n))
Step 3: Write monomial coefficients as BMP bytes.
"""
import sys, time
import numpy as np
import flint

MOD = 7514777789
Q1, Q2, Q3 = 998244353, 985661441, 469762049

def modinv(a, m):
    return pow(int(a), m - 2, m)

_twiddle_cache = {}

def get_twiddles(q, g, n, invert):
    key = (q, g, n, invert)
    if key in _twiddle_cache:
        return _twiddle_cache[key]
    BLOCK = 1024
    twiddles = []
    length = 2
    while length <= n:
        half = length >> 1
        w = pow(g, (q - 1) // length, q)
        if invert:
            w = modinv(w, q)
        wn = np.zeros(half, dtype=np.int64)
        wn[0] = 1
        limit = min(BLOCK, half)
        for k in range(1, limit):
            wn[k] = wn[k-1] * w % q
        if half > BLOCK:
            w_block = int(pow(w, BLOCK, q))
            for start in range(BLOCK, half, BLOCK):
                end = min(start + BLOCK, half)
                wn[start:end] = wn[start-BLOCK:start-BLOCK+(end-start)] * w_block % q
        twiddles.append(wn)
        length <<= 1
    _twiddle_cache[key] = twiddles
    return twiddles

def ntt(a, q, g, invert=False):
    n = len(a)
    j = 0
    for i in range(1, n):
        bit = n >> 1
        while j & bit:
            j ^= bit; bit >>= 1
        j ^= bit
        if i < j:
            a[i], a[j] = int(a[i]), int(a[j])
            a[i], a[j] = a[j], a[i]
    for wn in get_twiddles(q, g, n, invert):
        half = len(wn)
        length = half * 2
        blocks = a.reshape(-1, length)
        u = blocks[:, :half].copy()
        v = blocks[:, half:] * wn % q
        blocks[:, :half] = (u + v) % q
        blocks[:, half:] = (u - v) % q
    if invert:
        a[:] = a * modinv(n, q) % q

def poly_mult(A, B, q, g):
    sz = 1
    while sz < len(A) + len(B) - 1:
        sz <<= 1
    fa = np.zeros(sz, dtype=np.int64); fa[:len(A)] = A % q
    fb = np.zeros(sz, dtype=np.int64); fb[:len(B)] = B % q
    ntt(fa, q, g)
    ntt(fb, q, g)
    fc = fa * fb % q
    ntt(fc, q, g, invert=True)
    return fc

def compute_newton_coeffs(y, n):
    fact = [1] * (n + 1)
    for i in range(1, n+1):
        fact[i] = fact[i-1] * i % MOD
    inv_fact = [1] * (n + 1)
    inv_fact[n] = modinv(fact[n], MOD)
    for i in range(n-1, -1, -1):
        inv_fact[i] = inv_fact[i+1] * (i+1) % MOD

    # Must use Python ints: y[i]*inv_fact[i] can exceed int64_max
    A = np.array([int(y[i]) * inv_fact[i] % MOD for i in range(n)], dtype=np.int64)
    B = np.array([inv_fact[m] if m%2==0 else MOD-inv_fact[m] for m in range(n)], dtype=np.int64)

    C1 = poly_mult(A, B, Q1, 3)
    C2 = poly_mult(A, B, Q2, 3)
    C3 = poly_mult(A, B, Q3, 3)

    q1i2 = np.int64(modinv(Q1, Q2))
    Q12 = Q1 * Q2
    Q12i3 = np.int64(modinv(Q12 % Q3, Q3))
    Q12m = np.int64(Q12 % MOD)

    c1 = C1[:n].astype(np.int64)
    c2 = C2[:n].astype(np.int64)
    c3 = C3[:n].astype(np.int64)
    T2 = (c2 - c1) % np.int64(Q2) * q1i2 % np.int64(Q2)
    tmp = (c1 + np.int64(Q1) * T2) % np.int64(Q3)
    T3 = (c3 - tmp) % np.int64(Q3) * Q12i3 % np.int64(Q3)
    result = (c1 % np.int64(MOD) + np.int64(Q1) * T2 % np.int64(MOD) + Q12m * T3 % np.int64(MOD)) % np.int64(MOD)
    return result.tolist()

BASE = 64

def base_newton(a_list, mod):
    n = len(a_list)
    p = np.zeros(n, dtype=object)
    fall = np.zeros(n+1, dtype=object)
    fall[0] = 1
    for k in range(n):
        ak = int(a_list[k]) % mod
        p[:k+1] += ak * fall[:k+1]
        nf = np.zeros(k+2, dtype=object)
        nf[1:k+2] = fall[:k+1]
        nf[:k+1] -= k * fall[:k+1]
        fall[:k+2] = nf
    p %= mod; fall %= mod
    return (flint.nmod_poly(p.tolist(), mod),
            flint.nmod_poly(fall.tolist(), mod))

def newton_to_mono(a_list, mod):
    n = len(a_list)
    if n == 0:
        return (flint.nmod_poly([], mod), flint.nmod_poly([1], mod))
    if n <= BASE:
        return base_newton(a_list, mod)
    m = n // 2
    shift_poly = flint.nmod_poly([(-m) % mod, 1], mod)
    p_left, fall_left = newton_to_mono(a_list[:m], mod)
    q, fall_right = newton_to_mono(a_list[m:], mod)
    q_shifted = q.compose(shift_poly)
    fall_right_shifted = fall_right.compose(shift_poly)
    p = p_left + fall_left * q_shifted
    fall = fall_left * fall_right_shifted
    return (p, fall)

def main():
    raw = open('encoded.txt').read().strip().split('\n')
    n = len(raw)
    y = np.zeros(n, dtype=np.int64)
    for i, line in enumerate(raw):
        _, yi = line.split()
        y[i] = int(yi)

    a_coeffs = compute_newton_coeffs(y, n)

    sys.setrecursionlimit(500)
    p, _ = newton_to_mono(a_coeffs, MOD)

    coeffs = p.coeffs()
    out = bytes(int(c) for c in coeffs[:n-1])
    open('output.bmp', 'wb').write(out)

if __name__ == '__main__':
    main()
```

## Key Insights

1. **Consecutive integer x-values** unlock Newton forward differences, reducing interpolation from O(n²) to O(n log n).
2. **int64 overflow**: values near MOD ≈ 7.5e9 square to ~5.6e19 > int64_max, silently corrupting results. Always check numpy dtype limits when MOD > 3e9.
3. **python-flint** (FLINT bindings) provides fast polynomial composition (`nmod_poly.compose`) that makes the D&C Taylor shift approach practical.
