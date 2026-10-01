#!/usr/bin/env bash
# Spin up a per-challenge branch + scratch dir.
# Usage: ./new-chal.sh <category> <Challenge Name>
#   e.g. ./new-chal.sh web "JWT Forgery"
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

if [[ $# -lt 2 ]]; then
  echo "usage: $0 <category> <Challenge Name>" >&2
  echo "  e.g. $0 web \"JWT Forgery\"" >&2
  exit 1
fi

CAT="$(echo "$1" | tr '[:upper:]' '[:lower:]')"
SLUG="$(echo "$2" | tr '[:upper:]' '[:lower:]' | tr -cs '[:alnum:]' '-' | sed 's/-$//')"
BRANCH="chal/${CAT}-${SLUG}"
DIR="chal/${CAT}/${SLUG}"

if git show-ref --verify --quiet "refs/heads/$BRANCH"; then
  echo "[*] branch $BRANCH already exists — checking it out"
  git checkout "$BRANCH"
  exit 0
fi

git checkout main
git checkout -b "$BRANCH"

mkdir -p "$DIR"
cat > "$DIR/NOTES.md" <<EOF
# $2

- **Category:** $CAT
- **Branch:** \`$BRANCH\`
- **Target:**
- **Status:** in progress

## Observations

## Hypotheses

## Attempts

## Flag
EOF

git add "$DIR/NOTES.md"
git commit -q -m "chal($CAT): start $2

Co-Authored-By: Claude Code <noreply@anthropic.com>"
echo "[+] on branch $BRANCH, scratch dir $DIR"
