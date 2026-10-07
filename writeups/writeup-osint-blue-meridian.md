---
title: "Blue Meridian"
ctf: "Safaricom CTF"
date: 2026-10-06
category: osint
difficulty: hard
points: 750
flag_format: "safctf{...}"
author: "Strawhats"
---

# Blue Meridian

> **Category:** OSINT · **Points:** 750 · **Difficulty:** hard

## Discovery, analysis & exploitation

The full hunt below is reproduced from our working notes — recon, fingerprinting, the bug, dead ends, and the path to the flag.

Target: http://54.72.82.22:8500 (Flask/Werkzeug desk app)

## Surface
- `GET /` — landing page, "Collection desk" linking `GET /downloads/field-notes.zip`
- `GET /submit` → 405, `POST /submit {"answer": ...}` → 200 graded flag (desk app confirmed)

The page copy ("a single line cuts quietly across the familiar landscape") is the
hint for the *bearing* field; the puzzle itself lives entirely in the zip.

## The zip (field-notes.zip, 3857 B)
| file | role |
|---|---|
| `camera-metadata.json` | the identifier: `local_time 2026-06-04T21:00:00`, `utc_offset +02:00`, `compass_degrees 11`, `vessel_mark vessel-3` |
| `voyages.json` | 60 voyages: `ref, vessel, station, utc_hour, tide_cm, bearing` |
| `tide-station.csv` | station -> tide_cm (decoy-ish; keyed by the same station refs) |
| `civic-directory.json` | 36 houses keyed by the same station refs — pure decoy |
| `pier-note.txt` | "At the exposure, the gauge was 219 cm. Clock and compass had both been serviced that morning." (confirms clock/bearing are uncorrupted → use raw values) |
| `submission.txt` | receipt format `SHA256(voyage_ref\|station_ref\|UTC_time)` lowercase hex, `UTC_time` = `HH:MMZ` |

## Resolution
Filter `voyages.json` on the three camera fields:
`vessel == vessel-3`, `bearing == 11`, plus UTC hour from local+offset
(21:00 +02:00 → 19:00Z). Exactly one row matches:

```
{"ref": "d0b36031a079e290", "vessel": "vessel-3", "station": "5255073ff2",
 "utc_hour": 19, "tide_cm": 219, "bearing": 11}
```

`tide_cm 219` matches the pier-note gauge reading — a cross-check, not an input.

Receipt = `sha256("d0b36031a079e290|5255073ff2|19:00Z")`
        = `a037d4fd49143de5d5abbe38b536198ba777879089dd3b44dec83ac1b962c845`

`POST /submit {"answer": "<receipt>"}` → `200 {"message":"safctf{756f7d81426571a6d6dac9b1aae5f271}","ok":true}`

## Notes / gotchas
- No exploitation needed — the "OSINT" framing is flavour; the joining key is the
  shared `station`/`ref` namespace across the JSON/CSV files.
- The intermediate (the receipt hash) is accepted directly; the desk returns the
  graded `safctf{...}` flag.
- `field-notes.zip` is a binary and git-ignored; not committed.
  URL: `http://54.72.82.22:8500/downloads/field-notes.zip`
  SHA256: `659e0d481bb797d1474031c43ba2236fc2d8cc477b56dd8fb7789aa657466c89`

## Solve script

`osint/blue-meridian/solve.py`:

```python
#!/usr/bin/env python3
"""Blue Meridian (OSINT, 550) — http://54.72.82.22:8500

Collect field-notes.zip, pick the voyage that matches the camera artifact
(vessel + compass bearing, UTC time from local+offset, tide gauge reading),
then submit SHA256(voyage_ref|station_ref|HH:MMZ).
"""
import datetime, hashlib, io, json, zipfile, urllib.request

BASE = "http://54.72.82.22:8500"


def get(path):
    return urllib.request.urlopen(BASE + path, timeout=20).read()


def post_json(path, obj):
    req = urllib.request.Request(
        BASE + path, data=json.dumps(obj).encode(),
        headers={"Content-Type": "application/json"})
    try:
        r = urllib.request.urlopen(req, timeout=20)
        return r.status, r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()


def main():
    z = zipfile.ZipFile(io.BytesIO(get("/downloads/field-notes.zip")))
    notes = {n: z.read(n).decode() for n in z.namelist()}
    voyages = json.loads(notes["voyages.json"])
    cam = json.loads(notes["camera-metadata.json"])

    # local time -> UTC using the recorded offset
    off = cam["utc_offset"]                       # "+02:00"
    sign = 1 if off[0] == "+" else -1
    hh, mm = map(int, off[1:].split(":"))
    utc = datetime.datetime.fromisoformat(cam["local_time"]) - sign * datetime.timedelta(hours=hh, minutes=mm)

    matches = [v for v in voyages
               if v["vessel"] == cam["vessel_mark"]
               and v["bearing"] == cam["compass_degrees"]
               and v["utc_hour"] == utc.hour]
    assert len(matches) == 1, matches
    v = matches[0]

    receipt = hashlib.sha256(
        f"{v['ref']}|{v['station']}|{utc:%H:%M}Z".encode()).hexdigest()
    print("voyage", v)
    print("receipt", receipt)
    print(post_json("/submit", {"answer": receipt}))


if __name__ == "__main__":
    main()
```

## Tools

**Used in this solve:**

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
safctf{756f7d81426571a6d6dac9b1aae5f271}
```
