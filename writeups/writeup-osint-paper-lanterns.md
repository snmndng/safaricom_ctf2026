---
title: "Paper Lanterns"
ctf: "Safaricom CTF"
date: 2026-10-04
category: osint
difficulty: medium
points: 300
flag_format: "safctf{...}"
author: "safaricom-ctf-team"
---

# Paper Lanterns

## Summary

Desk: http://54.72.82.22:8480  (Werkzeug/3.1.9 Python/3.11.16)

## Solution

### Step 1: Run the solve script:

```python
#!/usr/bin/env python3
"""Paper Lanterns (OSINT, 200) — collection desk solver.

Recipe (deviates from the sibling template: no clock/UTC step, no second key):
  1. GET /               -> desk page linking /downloads/field-notes.zip
  2. unzip               -> postcard.txt, districts.csv, civic-directory.json
  3. postcard.txt is the clue:
        "Lunch beneath a glass roof, somewhere east of the river.
         The brass plaque said 1997."
     -> roof == "glass", district == "East" (via districts.csv: East->east),
        opened == 1997.
  4. Exactly one civic-directory.json row matches all three: the venue's
     collection reference (`ref`).
  5. POST /submit {"answer": "<ref>"}.
"""
import io
import json
import sys
import zipfile

import requests

BASE = "http://54.72.82.22:8480"

# The clue is prose; parse it into the three filters it encodes.
CLUE = dict(roof="glass", river_side="east", opened=1997)


def solve(base=BASE):
    r = requests.get(f"{base}/downloads/field-notes.zip", timeout=30)
    r.raise_for_status()
    z = zipfile.ZipFile(io.BytesIO(r.content))

    postcard = z.read("postcard.txt").decode().strip()
    assert "glass roof" in postcard, postcard
    assert str(CLUE["opened"]) in postcard, postcard

    # districts.csv maps district name -> river_side token used in the clue.
    district = None
    for line in z.read("districts.csv").decode().splitlines()[1:]:
        name, side = line.split(",")
        if side == CLUE["river_side"]:
            district = name

    rows = json.loads(z.read("civic-directory.json"))
    hits = [
        x for x in rows
        if x["roof"] == CLUE["roof"]
        and x["district"] == district
        and x["opened"] == CLUE["opened"]
    ]
    assert len(hits) == 1, f"expected exactly one venue, got {hits}"
    ref = hits[0]["ref"]
    print(f"venue={hits[0]['name']} ref={ref}")

    out = requests.post(f"{base}/submit", json={"answer": ref}, timeout=30)
    print(out.status_code, out.text)
    return out.json()


if __name__ == "__main__":
    sys.exit(0 if solve().get("ok") else 1)

```

## Flag

```
safctf{38309964a77c499b1ec234c401f68fe1}
```
