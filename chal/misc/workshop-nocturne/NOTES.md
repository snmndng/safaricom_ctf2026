# Workshop Nocturne (misc, linux-links)

**Flag:** `safctf{1cf16fdf78edcd426f2b8e008c329206}`

## Access
- Desk: http://54.72.82.22:8560/ (kind `linux-links`, web side is inert — every `/api/*` returns 404)
- SSH: `player@54.72.82.22:8720` / `matinee-visitor`
- Artifact: `http://54.72.82.22:8560/downloads/sample-job.tar`
  - sha256 `b4382a1c50d1db139a40560fb1e6a31775b0264327b86947e1786130db46e79a`
  - contains `manifest.json` (sha256 map), `manifest.sig` (HMAC-SHA256 hex), `task.sh`

## What the box is
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

## The bug (two parts)
1. **HMAC key is never needed.** The handed-out `sample-job.tar` is a genuine,
   organizer-signed archive. Reusing its `manifest.json` + `manifest.sig`
   verbatim satisfies the HMAC — no key recovery required.
2. **Symlinks bypass integrity.** The sha256 loop only inspects `item.isfile()`
   members. A tar member named `task.sh` of type SYMTYPE is skipped, so we omit
   the real `task.sh` entirely and ship only a symlink `task.sh ->
   /home/player/pwn.sh`. With `filter='fully_trusted'` the absolute symlink is
   created, and `/bin/sh <tmpdir>/task.sh` follows it, executing our script as
   root — which copies `/root/receipt` back to us.

## Steps
1. `pwn.sh` = `cp /root/receipt /home/player/receipt.out; chmod 644 ...`
2. Rebuild tar: original `manifest.json`, original `manifest.sig`, symlink
   `task.sh -> /home/player/pwn.sh` (no regular `task.sh` at all).
3. SFTP it to `/home/player/inbox/job.tar`; worker picks it up within ~1s.
4. `cat /home/player/receipt.out` -> flag.

`solve.py` does all of this end to end and prints the flag.

## Dead ends checked
`/root` 400, no sudo rights, no SUID beyond stock, no capabilities, no cron,
no second listener, `/opt`/`/srv` empty; web `/api/*` all 404 for `linux-links`
(and `/submit` compares against an `answer_hash` that settings.json omits, so
it can never pass). The only root path is the job worker.
