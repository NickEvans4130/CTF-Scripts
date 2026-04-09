# Small Private Exponent RSA (Wiener's Attack)

**Challenge:** Recover the flag from RSA parameters where the private exponent `d` is small.

**Files:** `encryption.py`, `message.txt`

**Flag:** `picoCTF{sm4ll_d_6ea2db76}`

---

## Vulnerability

The encryption script generates `d` first as a 256-bit prime, then derives `e = inverse(d, phi)`. This inverts the normal RSA setup — `e` becomes the large public exponent and `d` is the small private one. With `n` at 2096 bits and `d` at only 256 bits, Wiener's attack applies directly.

**Wiener's condition:** attack succeeds when `d < (1/3) * n^(1/4)`.
- `n^(1/4)` ≈ 524 bits
- `d` = 256 bits — well within range.

---

## No Existing Scripts Applied

There are currently no crypto scripts in this repository. The challenge was solved with a standalone implementation.

---

## Solution

Wiener's attack exploits the fact that when `d` is small, `k/d` (where `e*d = k*phi + 1`) appears as a convergent in the continued fraction expansion of `e/n`.

```python
from math import isqrt

def continued_fraction(num, den):
    while den:
        yield num // den
        num, den = den, num % den

def convergents(cf):
    n0, d0 = 0, 1
    n1, d1 = 1, 0
    for q in cf:
        n0, n1 = n1, q*n1 + n0
        d0, d1 = d1, q*d1 + d0
        yield n1, d1

def isqrt_exact(n):
    s = isqrt(n)
    return s if s * s == n else None

for k, d in convergents(continued_fraction(e, n)):
    if k == 0 or (e * d - 1) % k != 0:
        continue
    phi = (e * d - 1) // k
    b = n - phi + 1
    disc = b*b - 4*n
    if disc < 0:
        continue
    sq = isqrt_exact(disc)
    if sq is None:
        continue
    p, q = (b + sq) // 2, (b - sq) // 2
    if p * q == n:
        m = pow(c, d, n)
        flag = m.to_bytes((m.bit_length() + 7) // 8, 'big')
        # picoCTF{sm4ll_d_6ea2db76}
```

Recovered `d = 59503358581586301750515577934211170015981660485137211657473507426201919497329`.
