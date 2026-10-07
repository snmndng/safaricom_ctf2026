---
title: "Last Tram Home"
ctf: "Safaricom CTF"
date: 2026-10-06
category: osint
difficulty: hard
points: 500
flag_format: "safctf{...}"
author: "Strawhats"
---

# Last Tram Home

> **Category:** OSINT · **Points:** 500 · **Difficulty:** hard

## Discovery, analysis & exploitation

The full hunt below is reproduced from our working notes — recon, fingerprinting, the bug, dead ends, and the path to the flag.

## Endpoint
- Desk app: `http://54.72.82.22:8490`
- `GET /` — desk page linking `/downloads/field-notes.zip`
- Finale: `POST /submit {"answer":"<receipt>"}` → `200 {"message":"safctf{...}","ok":true}`

## Artifact
- `http://54.72.82.22:8490/downloads/field-notes.zip`
- sha256 `d70f0ace459bf26e7518bdf7ae4c79cdca50317415ebce1ef5b882532e3a655b`
- (binary kept out of git per repo .gitignore; extract manually with `unzip`)

Zip contents: `tram.csv`, `civic-directory.json`, `programme.json`,
`studio-post.txt`, `submission.txt`.

## Shape (same as Blue Meridian on :8500)
1. `studio-post.txt`: *"The last frame was taken at stop 18, three hours after
   UTC. The wall clock read 21:30 on 18 April 2026."*
   - local wall clock = UTC+3 → **UTC = 18:30 on 2026-04-18** (date unchanged).
2. `tram.csv`: `stop,venue` → stop **18** → venue_ref `b59c881fc2`.
3. `programme.json`: rows `{event, venue, time_utc, artist}`. Select the single
   row with `venue == b59c881fc2` **and** `time_utc == 2026-04-18T18:30:00Z`
   → event_ref **`2011bf1eeb4b`** (artist act-8). Exactly one match — no
   ambiguity, so no separate cross-confirm artifact was needed here.
4. `submission.txt`: *"Collection receipt format:
   SHA256(venue_ref|event_ref|UTC_date), lowercase hex."*
5. `receipt = sha256("b59c881fc2|2011bf1eeb4b|2026-04-18")`
   = `57aa623e8a9afd3082a959b18371e03ea717d6ad03f7e68948162fc507ee914d`
6. POSTed → flag.

## Notes / decoys
- `civic-directory.json` (venue metadata: name/district/roof/seats) is a decoy
  for the receipt — the hash does **not** use it. It is only a sanity anchor
  (ref `b59c881fc2` = "House 18", consistent with stop 18).
- `programme.json` repeats dates (April 1–20 then April 1–16 again) but
  `(venue, time_utc)` pairs are unique; the stop+time tuple uniquely selects
  the row, so the repeat-decoy does not bite.
- The key gotcha is the UTC conversion: wall clock 21:30 is local (UTC+3), so
  the matching `time_utc` is 18:30Z, **not** 21:30Z.

## Reproduce
```
python solve.py    # prints receipt and submits; expect ok:true + flag
```

## Solve script

`osint/last-tram-home/solve.py`:

```python
#!/usr/bin/env python3
"""Last Tram Home (OSINT, 300) -- solve.

Shape (mirrors Blue Meridian):
  studio-post.txt gives a stop number + a LOCAL wall clock + UTC offset.
  tram.csv: stop -> venue_ref
  programme.json: (venue_ref, time_utc) -> event_ref
  submission.txt: receipt = sha256("<venue_ref>|<event_ref>|UTC_date>")

  "The last frame was taken at stop 18, three hours after UTC.
   The wall clock read 21:30 on 18 April 2026."
   -> local = UTC+3 -> UTC = 18:30 2026-04-18 -> matches a programme row.
"""
import hashlib
import json

HERE = __import__("os").path.dirname(__file__)
EX = HERE + "/extracted"


def rows():
    prog = json.load(open(EX + "/programme.json"))
    tram = {}
    for line in open(EX + "/tram.csv").read().splitlines()[1:]:
        s, v = line.split(",")
        tram[s] = v
    return prog, tram


def main():
    prog, tram = rows()
    venue = tram["18"]
    # local 21:30 on 2026-04-18, local = UTC+3 -> UTC 18:30
    utc_date = "2026-04-18"
    utc_iso = "2026-04-18T18:30:00Z"
    match = [r for r in prog if r["venue"] == venue and r["time_utc"] == utc_iso]
    assert len(match) == 1, f"expected unique row, got {len(match)}: {match}"
    event = match[0]["event"]
    receipt = hashlib.sha256(f"{venue}|{event}|{utc_date}".encode()).hexdigest()
    print("venue_ref :", venue)
    print("event_ref :", event)
    print("utc_date  :", utc_date)
    print("receipt   :", receipt)
    return receipt


def submit(receipt, base="http://54.72.82.22:8490"):
    import json as _json
    import urllib.request

    req = urllib.request.Request(
        base + "/submit",
        data=_json.dumps({"answer": receipt}).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=20) as r:
        return r.status, r.read().decode()


if __name__ == "__main__":
    r = main()
    print(submit(r))
```

## Tools

**Used in this solve:**

- `hashlib`
- Python `urllib` (stdlib HTTP client)
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
safctf{a7290ed4a3ba7af7bd4b4c529eb99314}
```
