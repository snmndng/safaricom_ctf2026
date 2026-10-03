---
title: "Blue Meridian"
ctf: "Safaricom CTF"
date: 2026-10-04
category: osint
difficulty: hard
points: 750
flag_format: "safctf{...}"
author: "nomadspecter <the.nomad.specter@gmail.com>"
---

# Blue Meridian

## Summary

Target: http://54.72.82.22:8500 (Flask/Werkzeug desk app)

## Solution

### Step 1: Run the solve script:

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

## Flag

```
safctf{756f7d81426571a6d6dac9b1aae5f271}
```
