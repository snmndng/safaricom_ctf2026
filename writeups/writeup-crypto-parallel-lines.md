---
title: "Parallel Lines"
ctf: "Safaricom CTF"
date: 2026-10-06
category: crypto
difficulty: medium
points: 500
flag_format: "safctf{...}"
author: "Strawhats"
---

# Parallel Lines

> **Category:** CRYPTO · **Points:** 500 · **Difficulty:** medium

## Discovery, analysis & exploitation

The full hunt below is reproduced from our working notes — recon, fingerprinting, the bug, dead ends, and the path to the flag.

Target: http://54.72.82.22:8430 (Werkzeug/Flask)

## Material

`GET /downloads/lookbook.zip` yields four files:

| file            | size | contents |
|-----------------|------|----------|
| `memo.txt`      | 153  | 71 chars of prose: `Studio memo: sample garments arrive Tuesday. Keep the silver rack clear. ` followed by 82 `.` filler bytes |
| `export-a.bin`  | 153  | random-looking ciphertext |
| `export-b.bin`  | 64   | random-looking ciphertext |
| `spool.json`    | —    | `{"nonce":"ba2cbe7787a82ddb", "spool_order":[...153 ints...]}` |

`spool_order` is a permutation of `0..152` — the size of `export-a.bin`.
The `nonce` is 8 bytes (CTR-family width) but is not needed for the break.

`/submit` (POST JSON `{"answer": ...}`) is the checker; `/health` returns
`{"status":"ok"}`. Generic 404/405 elsewhere.

## Hypothesis tested and confirmed

The two exports are "parallel": **the same keystream is reused** (CTR nonce
reuse), and `export-a` was emitted out of spool order so it must be re-sorted
before it can be XORed against the known `memo.txt` plaintext.

1. Undo the permutation: `fixed[spool_order[i]] = export_a[i]`.
2. Recover the keystream: `ks = fixed XOR memo` (all 153 bytes of `memo`
   are known, including the `.` filler).
3. Decrypt the second export with the same keystream:
   `export_b XOR ks[:64]`.

Result:

```
Collection receipt: safctf{0983d7d0-b930-468f-ac25-ecc6feecc856}
```

The `safctf{...}` inside the receipt is **not** the challenge flag — it is a
receipt token. The checker only accepts that token:

```
POST /submit {"answer":"safctf{0983d7d0-b930-468f-ac25-ecc6feecc856}"}
-> {"message":"safctf{8d6447b3f694f59efef1f015f58d04a7}","ok":true}
```

Submitting the returned flag directly is rejected (`ok:false`), confirming the
receipt token is the input and the returned 32-hex value is the real flag.

## Attempts / dead ends (kept for the record)

- Raw (non-permuted) `export-a` XOR `memo` gave no structure.
- Applying the permutation in the other direction (`out[i] = a[order[i]]`) gave
  garbage; only the inverse mapping works.
- `export-a XOR export-b` (truncated) gave no structure — the reuse only
  becomes visible once `export-a` is re-sorted.

## Reproduction

```
python3 solve.py            # stdlib only, no deps
```

Dependencies: none beyond the Python standard library
(`urllib.request`, `json`, `zipfile`, `io`).

## Solve script

`crypto/parallel-lines/solve.py`:

```python
#!/usr/bin/env python3
"""Parallel Lines (CRYPTO, 500 pts) - Safaricom CTF.

Target: http://54.72.82.22:8430

Attack: keystream reuse across two "parallel" exports.
  * lookbook.zip contains memo.txt (known plaintext, 153 B, 71 readable
    chars + '.' filler), export-a.bin (153 B), export-b.bin (64 B) and
    spool.json which carries an 8-byte nonce and `spool_order`, a
    permutation of 0..152 applied to export-a's bytes.
  * Un-shuffle export-a with spool_order (out[spool_order[i]] = a[i]).
  * XOR the un-shuffled A with the memo => recovered keystream.
  * XOR export-b with the same keystream => "Collection receipt: <token>".
  * POST the receipt token to /submit; the service answers with the flag.

Stdlib only.  Usage:  python3 solve.py [target]
"""
import io
import json
import sys
import urllib.request
import zipfile


def fetch(url):
    with urllib.request.urlopen(url, timeout=30) as r:
        return r.read()


def unshuffle(data, order):
    out = bytearray(len(data))
    for i, pos in enumerate(order):
        out[pos] = data[i]
    return bytes(out)


def main():
    target = sys.argv[1] if len(sys.argv) > 1 else "http://54.72.82.22:8430"

    zf = zipfile.ZipFile(io.BytesIO(fetch(target + "/downloads/lookbook.zip")))
    memo = zf.read("memo.txt")
    a = zf.read("export-a.bin")
    b = zf.read("export-b.bin")
    spool = json.loads(zf.read("spool.json"))

    order = spool["spool_order"]
    a_fixed = unshuffle(a, order)

    keystream = bytes(x ^ y for x, y in zip(a_fixed, memo))
    receipt = bytes(x ^ y for x, y in zip(b, keystream[: len(b)])).decode()
    token = receipt.split(": ", 1)[1].strip()

    req = urllib.request.Request(
        target + "/submit",
        data=json.dumps({"answer": token}).encode(),
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=30) as r:
        print(json.loads(r.read())["message"])


if __name__ == "__main__":
    main()
```

## Tools

**Used in this solve:**

- Python `urllib` (stdlib HTTP client)
- `zipfile`
- Python 3 (solver)

**Other tools that fit this category:**

- SageMath (lattices, curves, polynomials)
- z3 (constraint solving)
- RsaCtfTool (RSA attacks)
- sympy / gmpy2 (number theory)
- fpylll (LLL/BKZ lattices)

## Flag

Intermediate answer: `safctf{0983d7d0-b930-468f-ac25-ecc6feecc856}`  
Graded flag: `safctf{8d6447b3f694f59efef1f015f58d04a7}`

```
safctf{8d6447b3f694f59efef1f015f58d04a7}
```
