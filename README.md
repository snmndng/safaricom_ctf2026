# Safaricom CTF — Working Repo

Workspace for the Safaricom CTF (51 challenges). One git branch per challenge so
multiple Claude Code sessions can work in parallel without stepping on each other.

## Layout

```
.
├── CHALLENGES.md        # full board + triage (which we start with, and why)
├── WRITEUPS/            # completed writeups, one dir per challenge
├── chal/                # per-challenge scratch (payloads, scripts, notes)
├── tools/               # shared helper scripts
└── new-chal.sh          # spin up a challenge branch + dir
```

## Branch model

| Branch | Purpose |
| --- | --- |
| `main` | index, shared notes, tooling, WRITEUPS. Nothing challenge-specific. |
| `chal/<slug>` | one challenge, branched from `main`. |

Each parallel session does `./new-chal.sh <category> <slug>` and stays on that
branch. Merge to `main` only when the flag is captured (writeup + solve script).

## Running multiple sessions

Terminal 1..N, each:
```sh
cd /home/nomad/safaricom_ctf
git checkout chal/<slug>     # or ./new-chal.sh to create it
claude
```

Each session owns exactly one `chal/*` branch. Merge back to `main` when solved.

## Status

- Solved: 0 / 51

See `CHALLENGES.md` for the triage and recommended start order.
