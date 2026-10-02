# In-flight leads at halt (2026-10-02)

Captured because the session was halted to rotate the API key, and agent
context does not survive a restart. Leads are **unverified** — the agent that
produced each was killed mid-thought.

| Challenge | Port | Last state before halt |
| --- | --- | --- |
| Long Exposure | 8470 | *"The NOI packets may be stacked noise frames — a per-position bias would be the 'long exposure' reveal."* Suggests many frames + averaging/bias per pixel position. |
| Photo Finish | 8350 | *"8350 is a Nessus, not a desk app."* — i.e. the banner is a Nessus scanner, so `:8350` may be the wrong target or a red herring. Needs re-fingerprinting before more work. |
| Backstage Ledger | 8340 | Killed immediately after launch; no findings. |
| Citrus Proof | 8320 | *"Use the sibling RCE (port 8050, already solved) as a pivot to look for the host Docker API."* Wild idea, unverified — treat with suspicion. |

## Worktrees holding unmerged partial work

Each is a live git worktree under `.claude/worktrees/`; branches still exist.
The **first** Citrus Proof attempt (dead on quota) also holds its own worktree
with ~28 min of fuzzing scripts, and owns the branch name `chal/web/citrus-proof`.

- `agent-a264bf47aea27b87d` — Long Exposure
- `agent-a71a57903033994ef` — Photo Finish
- `agent-a3077f6eccc9255de` — Backstage Ledger
- `agent-afda0e95a4bb87565` — Citrus Proof (second attempt)
- `agent-a95bab3e0254bbe9c` — Citrus Proof (first attempt, has fuzzers)

## State at halt

Board **40 solved / 45 flags**, HEAD `510619b`, working tree clean apart from
untracked `.ignore`, `.mcp.json`, `Remaining_challenges.md`.
