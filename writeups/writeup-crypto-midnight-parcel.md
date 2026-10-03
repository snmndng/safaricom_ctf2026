---
title: "Midnight Parcel"
ctf: "Safaricom CTF"
date: 2026-10-04
category: crypto
difficulty: hard
points: 750
flag_format: "safctf{...}"
author: "nomadspecter <the.nomad.specter@gmail.com>"
---

# Midnight Parcel

## Summary

Target: `http://54.72.82.22:8440` (Werkzeug/Flask)

## Solution

### Step 1: Run the solve script:

```python
#!/usr/bin/env python3
"""
Midnight Parcel (crypto, 750) -- CBC padding oracle.

Served at /api/receipt: POST a hex "parcel"; a parcel whose PKCS#7 padding is
valid returns {"status":"pending"} (HTTP 202), invalid padding returns
{"status":"damaged"} (HTTP 422).  That is a textbook CBC padding oracle.

Because the oracle only ever inspects the *final* block's padding, we recover
the last block by varying the block in front of it, then truncate the ciphertext
so that each earlier block becomes the final block in turn.
"""
import json, urllib.request, urllib.error, concurrent.futures

T = "http://54.72.82.22:8440"
WORKERS = 32


def status(ct):
    data = json.dumps({"parcel": ct.hex()}).encode()
    req = urllib.request.Request(T + "/api/receipt", data=data,
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            return json.loads(r.read()).get("status")
    except urllib.error.HTTPError as e:
        try:
            return json.loads(e.read()).get("status")
        except Exception:
            return "?"
    except Exception:
        return None


def recover_block(ct, blk):  # ct = blocks[0..blk], blk = index of target block
    """Recover D(C_blk) by mutating block blk-1; returns 16-byte bytearray."""
    n = len(ct) // 16
    assert blk == n - 1 and blk >= 1
    D = bytearray(16)
    prev_off = (blk - 1) * 16

    for pos in range(15, -1, -1):
        L = 16 - pos  # desired padding length/value

        def trial(v):
            b = bytearray(ct)
            b[prev_off + pos] = v
            for k in range(pos + 1, 16):
                b[prev_off + k] = D[k] ^ L
            return status(b)

        with concurrent.futures.ThreadPoolExecutor(WORKERS) as ex:
            res = list(ex.map(trial, range(256)))
        valid = [v for v, s in enumerate(res) if s == "pending"]

        if L == 1 and len(valid) > 1:
            # disambiguate real 0x01 padding from a coincidental 0x02 pad
            def confirm(v):
                b = bytearray(ct)
                b[prev_off + 15] = v
                b[prev_off + 14] ^= 1  # only 0x01 padding survives this
                return status(b)
            with concurrent.futures.ThreadPoolExecutor(WORKERS) as ex:
                conf = list(ex.map(confirm, valid))
            valid = [v for v, s in zip(valid, conf) if s == "pending"]

        assert len(valid) == 1, (pos, valid)
        D[pos] = valid[0] ^ L
    return D


def main():
    P = json.load(urllib.request.urlopen(T + "/api/parcel"))["parcel"]
    CT = bytearray.fromhex(P)
    blocks = [bytes(CT[i * 16:(i + 1) * 16]) for i in range(len(CT) // 16)]
    nb = len(blocks)
    print(f"[*] ciphertext: {len(CT)} bytes, {nb} blocks")

    plain = {}  # block index -> plaintext bytes
    for i in range(nb - 1, 0, -1):
        trunc = b"".join(blocks[:i + 1])
        D = recover_block(trunc, i)
        Pt = bytes(d ^ c for d, c in zip(D, blocks[i - 1]))
        plain[i] = Pt
        print(f"[+] block {i}: {Pt!r}")

    print("\n[*] decrypted (blocks 1..%d):" % (nb - 1))
    joined = b"".join(plain[i] for i in sorted(plain))
    print(repr(joined))
    print(joined.decode("latin-1"))

    import re
    m = re.search(rb"safctf\{[0-9a-f]{32}\}", joined)
    if m:
        print("\nFLAG:", m.group().decode())
    else:
        # also scan for the UUID-shaped variant
        m = re.search(rb"safctf\{[0-9a-f-]{36}\}", joined)
        print("\nFLAG:", m.group().decode() if m else "not in blocks 1..n")

# ... (truncated)
```

## Flag

```
safctf{8a99e6bb-7903-4f4e-b42a-7e594982528b}
```
