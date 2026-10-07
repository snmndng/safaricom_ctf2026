---
title: "Paper Lanterns"
ctf: "Safaricom CTF"
date: 2026-10-06
category: osint
difficulty: medium
points: 300
flag_format: "safctf{...}"
author: "Strawhats"
---

# Paper Lanterns

> **Category:** OSINT · **Points:** 300 · **Difficulty:** medium

## Discovery, analysis & exploitation

The full hunt below is reproduced from our working notes — recon, fingerprinting, the bug, dead ends, and the path to the flag.

Desk: http://54.72.82.22:8480  (Werkzeug/3.1.9 Python/3.11.16)

## Result

- Submitted: `POST /submit` JSON `{"answer": "ba57ce94e3"}` -> `200 {"ok":true}`

## Deviation from the sibling template

The brief predicted: identifier in a note + local wall-clock/UTC-offset ->
convert to UTC -> CSV join -> JSON row -> `submission.txt` hash recipe.
**This challenge has none of that.** Specifically:

- No time component anywhere; no UTC conversion step.
- No second key / no CSV->JSON join by identifier. `districts.csv` is a
  4-row lookup (`district,river_side`) used only to decode the river word.
- No `submission.txt`, no stated hash recipe. The answer is the raw `ref`
  string, not a hash.
- `civic-directory.json` is NOT a decoy here — it is the actual target list.

## Endpoints / files

| Where | What |
|---|---|
| `GET /` | Desk page ("Collection desk" + "Leave a receipt" form) |
| `GET /downloads/field-notes.zip` | The only artifact. sha256 `6c3e8ba1537987f604331173138328a9cf76944fa0351d35465bc41ef66577a8` |
| `POST /submit` | `{"answer": ...}`; 200 `ok:true` only for the correct value, else 403 |
| `GET /submit` | 405 (confirms desk app, not WAF-blocked) |

Probed and 404: `/robots.txt`, `/sitemap.xml`, `/downloads/`, `/hint`,
`/notes`, `/api`, `/README`, `/static/`. Nothing else served.

## The solve

Zip contents: `postcard.txt`, `districts.csv`, `civic-directory.json` (36 rows).

`postcard.txt`:
> Lunch beneath a glass roof, somewhere east of the river. The brass plaque said 1997.

`districts.csv`: `North,north / East,east / South,south / West,west`

Three filters fall out of the prose:
- "glass roof" -> `roof == "glass"`
- "east of the river" -> `river_side == "east"` -> `district == "East"`
- "brass plaque said 1997" -> `opened == 1997`

Exactly one row in `civic-directory.json` satisfies all three:
`{"ref": "ba57ce94e3", "name": "House 18", "district": "East", "opened": 1997, "roof": "glass", "seats": 307}`

The desk asks for the "collection reference", i.e. `ref` — submitted verbatim.

## Where I got stuck / notes

- Nothing actually blocked; the only friction was that the template recipe
  didn't apply. Confirms: when a note has prose instead of a timestamp, treat
  the adjectives as the join filters rather than looking for a clock.
- `House 18` / `House18` both 403 — only the `ref` is accepted.

## Reproduce

```
/home/nomad/safaricom_ctf/.venv/bin/python solve.py
```

## Solve script

`osint/paper-lanterns/solve.py`:

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

## Tools

**Used in this solve:**

- `zipfile`
- Python `requests` (HTTP client)
- Python 3 (solver)

**Other tools that fit this category:**

- exiftool (media metadata)
- the Wayback Machine / archive.today
- Google/GitHub dorking
- sherlock / maigret (username pivots)
- reverse image search (Yandex/Google)
- whois / crt.sh / dnsrecon

## Flag

```
safctf{38309964a77c499b1ec234c401f68fe1}
```
