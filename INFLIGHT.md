# In-flight leads at halt (2026-10-02, second halt — API key rotation)

Captured because the session was halted to swap the API key. Agent context does
not survive a restart. Leads are **unverified** — the agent that produced each was
killed mid-thought.

## Halted agents

| Challenge | Port | Agent id | Last state before halt |
| --- | --- | --- | --- |
| Backstage Ledger | 8340 | `a9ba573fb946b8e99` | Enumerating its own API surface — probing `/api/profile` with `X-Session`/`user`/`profile`/`demo`/`debug` params, then root-level data files and `/downloads`, `/static`. No flag. |
| Orchard Society | 8570 | `a08fb90f2302f379e` | *"Read the solved siblings' NOTES to learn the exact receipt-recipe convention, then shotgun-hash."* — i.e. it had concluded the answer is a derived receipt, not a brute-forced secret. No flag. |

Both can be resumed with SendMessage to their agent id **if the session survives
the key swap**; otherwise their worktrees persist on disk.

## Solved during this halt

**Citrus Proof (:8320, 550) — SOLVED.** Flag
`safctf{83f575a861a0c69d675d700dcb658cd2}`, committed `fe13c7b`, merged `d46153d`,
board `5a6fbc0`. Its agent was killed *as it was about to commit* — the solve was
recovered from its worktree and independently re-verified before landing.

The bug: the JWT verifier **trusts a signing key supplied in the header**
(`head['jwk']['k']`), so a `{"role":"curator"}` token is self-signed, not cracked.
The leak came from sibling challenge **Touchline Dispatch (:8300)**'s path
traversal reading `/app/service.py`. Curator + `/api/proof` = Jinja2 SSTI with
`_ [ ]` filtered, dodged via `|attr()` with names taken from query args.

## Gotcha hit while landing Citrus Proof

`land.sh <branch>` merges the **named branch**, not your worktree's
`worktree-agent-<id>` branch. The first Citrus attempt still had
`chal/web-citrus-proof` checked out in its own worktree, so `git branch -f`
refused and `land.sh chal/web-citrus-proof` merged an *empty* branch — flipping
TARGETS.md to "solved" with no flag and no NOTES update. TARGETS.md lied for one
commit. **Always check `git merge-base --is-ancestor <your-commit> main` after a
land, and grep FLAGS.md for the flag.**

`chal/web-citrus-proof` still points at the **stale first attempt** (`5b17ec0`),
not the solve. The canonical solve is `fe13c7b` / merged as `d46153d`. Do not
re-land that branch name.

## Still open in scope

- **Long Exposure (8470, 350)** — deep negative; blocker is structural (no seed in
  any shipped file). Needs a new input, not a new agent.
- **Path Least Travelled (8000)** — connection refused on every probe, including
  this halt. Down.
- **Mr Beast (8110), Photo Finish (8350)** — blocked as deployed, do not re-attempt.

## State at halt

Board **51 solved / 59 flags**, HEAD `5a6fbc0`, working tree clean apart from
untracked `.ignore`, `.mcp.json`, `Remaining_challenges.md`.

49 worktrees remain under `.claude/worktrees/` — most are finished solves whose
branches are already merged and could be pruned.
