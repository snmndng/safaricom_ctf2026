---
title: "Fragments"
ctf: "Safaricom CTF"
date: 2026-10-04
category: ai-ml
difficulty: medium
points: 300
flag_format: "safctf{...}"
author: "nomadspecter <the.nomad.specter@gmail.com>"
---

# Fragments

## Summary

- Target: `http://54.72.82.22:8190`

## Solution

### Step 1: Run the solve script:

```python
#!/usr/bin/env python3
"""Fragments (AI, 150) - http://54.72.82.22:8190

The /ask endpoint always replies with a canned "I don't recall anything
unusual" line, except when the prompt contains a memory-related keyword
(memory / recall / history). Then the "AI" recovers the missing conversation
and returns the flag.
"""
import re
import requests

URL = "http://54.72.82.22:8190/ask"

def main():
    for probe in ("memory", "recall", "history"):
        r = requests.post(URL, json={"prompt": probe}, timeout=20)
        r.raise_for_status()
        m = re.search(r"safctf\{[0-9a-f]{32}\}", r.text)
        if m:
            print(f"[+] trigger={probe!r}")
            print(f"[+] {m.group(0)}")
            return m.group(0)
    raise SystemExit("[-] no flag found")

if __name__ == "__main__":
    main()

```

## Flag

```
safctf{d432e09718e6cb46387f54e27dbc0168}
```
