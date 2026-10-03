---
title: "Last Tram Home"
ctf: "Safaricom CTF"
date: 2026-10-04
category: osint
difficulty: hard
points: 500
flag_format: "safctf{...}"
author: "Strawhats"
---

# Last Tram Home

## Summary

**Flag:** `safctf{a7290ed4a3ba7af7bd4b4c529eb99314}`

## Solution

### Step 1: Run the solve script:

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

## Flag

```
safctf{a7290ed4a3ba7af7bd4b4c529eb99314}
```
