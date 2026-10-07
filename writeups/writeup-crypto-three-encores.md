---
title: "Three Encores"
ctf: "Safaricom CTF"
date: 2026-10-06
category: crypto
difficulty: medium
points: 300
flag_format: "safctf{...}"
author: "Strawhats"
---

# Three Encores

> **Category:** CRYPTO · **Points:** 300 · **Difficulty:** medium

## Discovery, analysis & exploitation

The full hunt below is reproduced from our working notes — recon, fingerprinting, the bug, dead ends, and the path to the flag.

Target: http://54.72.82.22:8420 (Flask/Werkzeug 3.1.9)

## Recon

`GET /` is a themed landing page titled **Three Encores**, tagline
"A familiar melody in three different rooms." One download link:
`/downloads/programme.json`. `/download`, `/file`, `/static/`, `/robots.txt`
are all 404. `/submit` accepts `POST` with JSON `{"answer": ...}`.

## The material

`programme.json` contains `deliveries`: **three** RSA records, each with
`n`, `e`, `c`. Every record has `e = 3`, and — critically — **all three `c`
values are byte-identical**.

## Solving

Classic setup for the **Håstad broadcast attack** (e=3, three moduli, same
plaintext). But it collapses immediately:

- `c` is 1293 bits, each `n` is ~1535–1536 bits.
- Since `c` is identical across all three moduli and `m^3 = c` fits in
  ~1293 bits (**under** every `n`), there is no modular reduction at all:
  the ciphertext *is* `m^3`.
- A plain integer cube root recovers `m` exactly (the CRT over the three
  moduli gives the same number, `k=0` branch).

```
m = 0x70726f6772616d6d653a7361666374667b...  (431-bit integer)
  = b"programme:safctf{dadb56ae-eede-422e-87cb-744462cdfda0}"
```

### Three "encores"

The title is a decoy: the three deliveries are not three distinct layers —
they are the same layer repeated three times, and the naive e-th root works
without any CRT.

## Getting the scored flag

The decrypted blob carries an *intermediate* value. `POST /submit` with
`{"answer": "safctf{dadb56ae-eede-422e-87cb-744462cdfda0}"}` (the inner
`programme:safctf{...}` prefix must be stripped — the bare `safctf{...}`
inner flag is the accepted answer) returns:

```json
{"message": "safctf{0471ad15e84bb9f630e394e49dde85a9}", "ok": true}
```

A wrong answer returns `{"message": "The request could not be completed.", "ok": false}`.
The returned flag is stable across repeat submissions and matches the expected
`safctf{` + 32 hex + `}` format.

## Reproduce

```
python3 chal/crypto/three-encores/solve.py
```

Stdlib only (urllib) — no pycryptodome/gmpy2/sympy required.

## Solve script

`crypto/three-encores/solve.py`:

```python
#!/usr/bin/env python3
"""
Three Encores (CRYPTO, 300 pts)  --  http://54.72.82.22:8420

Chain
-----
1. GET /downloads/programme.json  ->  three RSA "deliveries", all e=3 and
   (surprisingly) an IDENTICAL ciphertext c.
2. No multi-modulus CRT needed: |m^3| = 1293 bits < n (~1535 bits), so the
   ciphertext is literally m^3 with no modular reduction.  A plain integer
   cube root recovers m.
3. m = b"programme:safctf{dadb56ae-eede-422e-87cb-744462cdfda0}" -- the inner
   flag.  POSTing that inner value to /submit returns the scored flag:
       safctf{0471ad15e84bb9f630e394e49dde85a9}

Reproduces end-to-end with only the stdlib (urllib), no gmpy2/sympy needed.
"""

import json
import re
import urllib.request

BASE = "http://54.72.82.22:8420"
PROGRAMME = BASE + "/downloads/programme.json"
SUBMIT = BASE + "/submit"


def http_get(url):
    with urllib.request.urlopen(url, timeout=30) as r:
        return r.read()


def http_post_json(url, obj):
    data = json.dumps(obj).encode()
    req = urllib.request.Request(url, data=data,
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.loads(r.read())


def iroot(n, k):
    """Integer k-th root, exact floor."""
    if n == 0:
        return 0
    x = 1 << ((n.bit_length() + k - 1) // k)
    while True:
        y = ((k - 1) * x + n // x ** (k - 1)) // k
        if y >= x:
            break
        x = y
    while x ** k > n:
        x -= 1
    while (x + 1) ** k <= n:
        x += 1
    return x


def main():
    prog = json.loads(http_get(PROGRAMME))
    ds = prog["deliveries"]

    cs = {d["c"] for d in ds}
    es = {d["e"] for d in ds}
    print(f"[*] {len(ds)} deliveries, e values={es}, distinct ciphertexts={len(cs)}")

    c = int(ds[0]["c"], 16)
    e = ds[0]["e"]

    # Plain integer e-th root (works because m^e < n here, no mod reduction).
    m = iroot(c, e)
    assert m ** e == c, "not an exact root -- would need Hastad CRT over all n"
    print(f"[*] exact {e}-th root recovered m = {m.bit_length()} bits")

    h = format(m, "x")
    if len(h) % 2:
        h = "0" + h
    blob = bytes.fromhex(h)
    inner = blob.decode(errors="replace")
    print(f"[*] decrypted: {inner!r}")

    # The blob carries an intermediate flag with a "programme:" prefix;
    # /submit only accepts the bare inner safctf{...} (403 on anything else).
    mt = re.search(rb"safctf\{[^}]*\}", blob)
    if not mt:
        print("[!] no safctf{...} found in decrypted blob")
        return
    answer = mt.group(0).decode()
    print(f"[*] submitting answer: {answer}")
    try:
        resp = http_post_json(SUBMIT, {"answer": answer})
    except urllib.error.HTTPError as ex:
        print(f"[!] /submit HTTP {ex.code}: {ex.reason}")
        return
    print(f"[*] /submit -> {resp}")

    if resp.get("ok"):
        print(f"[+] FLAG: {resp['message']}")
    else:
        print(f"[!] submit rejected; decrypted value was {inner}")


if __name__ == "__main__":
    main()
```

## Tools

**Used in this solve:**

- Python `urllib` (stdlib HTTP client)
- Python 3 (solver)

**Other tools that fit this category:**

- SageMath (lattices, curves, polynomials)
- z3 (constraint solving)
- RsaCtfTool (RSA attacks)
- sympy / gmpy2 (number theory)
- fpylll (LLL/BKZ lattices)

## Flag

Intermediate answer: `safctf{0471ad15e84bb9f630e394e49dde85a9}`  
Graded flag: `safctf{dadb56ae-eede-422e-87cb-744462cdfda0}`

```
safctf{dadb56ae-eede-422e-87cb-744462cdfda0}
```
