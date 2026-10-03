---
title: "Three Encores"
ctf: "Safaricom CTF"
date: 2026-10-04
category: crypto
difficulty: medium
points: 300
flag_format: "safctf{...}"
author: "Strawhats"
---

# Three Encores

## Summary

Target: http://54.72.82.22:8420 (Flask/Werkzeug 3.1.9)

## Solution

### Step 1: Run the solve script:

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

# ... (truncated)
```

## Flag

```
safctf{0471ad15e84bb9f630e394e49dde85a9}
```
