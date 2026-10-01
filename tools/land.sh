#!/usr/bin/env bash
# land.sh <branch> [port] [status-note] — the deterministic half of a solve.
#
# Merge an agent's branch, refresh FLAGS.md, flip that port's row in TARGETS.md
# to solved, recount CHALLENGES.md, and commit. Doing this by hand burned
# orchestrator tokens on work a script does exactly.
#
#   tools/land.sh chal/web-inner-joiner 8170 "SQLi in /lookup?name="
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

branch="${1:?usage: land.sh <branch> [port] [status-note]}"
port="${2:-}"
note="${3:-}"

if ! git rev-parse --verify --quiet "$branch" >/dev/null; then
  echo "land.sh: no such branch: $branch" >&2
  exit 1
fi

# 1. Merge. --no-ff keeps the per-challenge branch legible in history.
git merge --no-ff "$branch" -m "Merge $branch (solved)

Co-Authored-By: Claude Code <noreply@anthropic.com>"

# 2. Refresh the durable flag record.
python3 tools/flags.py
n=$(python3 tools/flags.py --count)

# 3. Flip the target's row, if a port was given.
if [[ -n "$port" ]]; then
  python3 - "$port" "$note" <<'PY'
import re, sys
port, note = sys.argv[1], sys.argv[2]
p = "TARGETS.md"
s = open(p).read()
row = re.compile(r"^\| " + re.escape(port) + r" \| ([^|]+)\| (todo|\?|solved) \|([^|]*)\|$",
                 re.M)
m = row.search(s)
if not m:
    print(f"TARGETS.md: no row for port {port} — add it by hand")
else:
    name = m.group(1).strip()
    s = row.sub(f"| {port} | {name} | solved | {note or 'see chal/ NOTES.md'} |", s, count=1)
    open(p, "w").write(s)
    print(f"TARGETS.md: {port} {name} -> solved")
PY
fi

# 4. Recount the board header from FLAGS.md's challenge count.
python3 - "$n" <<'PY'
import re, sys
n = sys.argv[1]
p = "CHALLENGES.md"
s = open(p).read()
s2 = re.sub(r"Solved: \d+ —", f"Solved: {n} —", s, count=1)
s2 = re.sub(r"^Solved \(\d+\):", f"Solved ({n}):", s2, count=1, flags=re.M)
open(p, "w").write(s2)
print(f"CHALLENGES.md: solved -> {n}")
PY

# 5. One commit for the bookkeeping.
git add -A
if git diff --cached --quiet; then
  echo "land.sh: nothing to commit (board already current)"
else
  git commit -q -m "board: land $branch — $n solved

Co-Authored-By: Claude Code <noreply@anthropic.com>"
fi
git log --oneline -1
