---
title: "Ticket Carousel"
ctf: "Safaricom CTF"
date: 2026-10-04
category: misc
difficulty: medium
points: 300
flag_format: "safctf{...}"
author: "Strawhats"
---

# Ticket Carousel

## Summary

A 40-state deterministic automaton, handed to you in the open. The desk page

## Solution

### Step 1: A 40-state deterministic automaton, handed to you in the open. The desk page

```python
#!/usr/bin/env python3
"""Ticket Carousel (desk app :8630) — reach the DFA's closing state.

The desk serves `/downloads/carousel.map`, a 40-state deterministic automaton:

    {"initial": 0, "closing": 39, "table": {"0": {"A": 4, "B": 31, ...}, ...}}

`POST /api/round` mints a round id; `POST /api/move {"round","symbol"}` steps the
automaton from `initial` and answers `{"position": n}`.  Stepping into the
`closing` state ends the round with `{"message": "Round complete: safctf{...}"}`.

So the challenge is just: BFS the map from `initial` to `closing`, then replay
that symbol path against the live API.  (Shortest path happens to be `DAB`:
0 -D-> 27 -A-> 36 -B-> 39.)
"""
import collections
import json
import sys
import urllib.request

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://54.72.82.22:8630"


def post(path, obj):
    req = urllib.request.Request(BASE + path, data=json.dumps(obj).encode(),
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=15) as r:
        return json.loads(r.read().decode())


def main():
    with urllib.request.urlopen(BASE + "/downloads/carousel.map", timeout=15) as r:
        m = json.load(r)
    table, start, goal = m["table"], str(m["initial"]), str(m["closing"])

    # BFS for the shortest symbol path start -> goal.
    prev, q = {start: None}, collections.deque([start])
    while q:
        u = q.popleft()
        if u == goal:
            break
        for sym, v in table[u].items():
            v = str(v)
            if v not in prev:
                prev[v] = (u, sym)
                q.append(v)
    if goal not in prev:
        print("[!] closing state unreachable")
        return 1
    path, cur = [], goal
    while prev[cur]:
        cur, sym = prev[cur]
        path.append(sym)
    path.reverse()
    print("[*] shortest path: %s (%d moves)" % ("".join(path), len(path)))

    rid = post("/api/round", {})["round"]
    for sym in path[:-1]:
        post("/api/move", {"round": rid, "symbol": sym})
    res = post("/api/move", {"round": rid, "symbol": path[-1]})
    print("[+]", res.get("message", res))
    return 0


if __name__ == "__main__":
    sys.exit(main())

```

### Step 2: A 40-state deterministic automaton, handed to you in the open. The desk page

A 40-state deterministic automaton, handed to you in the open. The desk page
links `/downloads/carousel.map`:
```json
{"initial": 0, "closing": 39,
 "table": {"0": {"A": 4, "B": 31, "C": 21, "D": 27}, ... "39": {...}}}
```
API (both JSON in, JSON out):




An unknown/missing symbol is ignored (you stay at the current position), so
there is no injection surface here — the puzzle is purely "walk the map".

## Flag

```
safctf{5b701cd93c298559638b8b4181bfa5e2}
```
