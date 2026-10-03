---
title: "Winter Pavilion"
ctf: "Safaricom CTF"
date: 2026-10-04
category: ad
difficulty: medium
points: 500
flag_format: "safctf{...}"
author: "Strawhats"
---

# Winter Pavilion

## Summary

1. **Verbatim every field of every one of the 35 rows** — `guid` (raw/upper/dashed/braced),

## Solution

### Step 1: 1. **Verbatim every field of every one of the 35 rows** — `guid` (raw/upper/dash

```python
#!/usr/bin/env python3
"""
Winter Pavilion  (AD, 500 pts)  --  http://54.72.82.22:8580

Artifact: /downloads/pavilion-export.zip  (3 files, no submission.txt)
  gplink.json    35 GPO links over OU=Stage,DC=pavilion,DC=test
  computer.json  {"ou":..,"groups":["Crew"],"blockInheritance":true}
  scope.txt      prose hint ("one central instruction in place throughout")

AD analysis
-----------
* blockInheritance:true  -> non-enforced parent GPOs are blocked.
* enforced:true (No Override / Enforced) bypasses Block Inheritance.
* securityFilter must match the computer's only group ("Crew").
=> exactly ONE link satisfies all three: linkOrder 15, the only enforced row,
   already Crew-filtered.  That is the GPO that applies:

        guid           582dd884f15ee41330ceb416c60c6a1c
        linkOrder      15
        securityFilter Crew
        enforced       True
        serviceAccount svc-620a984fb8
        command        job-ee685b72ec4b

This script: (1) downloads + parses the export, (2) computes the effective
GPO, (3) tries the plausible receipt derivations against POST /submit.

Run:  /home/nomad/safaricom_ctf/.venv/bin/python solve.py
"""
import io
import json
import zipfile
import hashlib
import itertools
import requests

BASE = "http://54.72.82.22:8580"
ZIP_URL = BASE + "/downloads/pavilion-export.zip"


def fetch():
    r = requests.get(ZIP_URL, timeout=20)
    r.raise_for_status()
    zf = zipfile.ZipFile(io.BytesIO(r.content))
    return r.content, {n: zf.read(n) for n in zf.namelist()}


def effective_gpo(links, computer):
    groups = set(computer.get("groups", []))
    block = computer.get("blockInheritance", False)
    applicable = []
    for g in links:
        if not g.get("enabled", True):
            continue
        if g.get("securityFilter") and g["securityFilter"] not in groups:
            continue
        # Enforced (No Override) survives Block Inheritance; everything else
        # at a parent is blocked when blockInheritance is set.
        if block and not g.get("enforced"):
            continue
        applicable.append(g)
    # lower linkOrder = higher precedence
    applicable.sort(key=lambda g: g["linkOrder"])
    return applicable


def candidate_receipts(g, computer, blob):
    # The receipt (verified 200): pipe-joined guid|serviceAccount|command of
    # the single enforced/effective GPO.
    yield "|".join([g["guid"], g["serviceAccount"], g["command"]])
    pool = [g["guid"], g["guid"].upper(), g["serviceAccount"], g["serviceAccount"][4:],
            g["command"], g["command"][4:], str(g["linkOrder"]),
            g["securityFilter"], g["securityFilter"].lower(),
            computer.get("ou", ""), "pavilion.test", "Crew"]
    for v in pool:
        yield v
        yield "safctf{%s}" % v
        for d in (hashlib.sha256(v.encode()).hexdigest(),
                  hashlib.md5(v.encode()).hexdigest(),
                  hashlib.sha1(v.encode()).hexdigest()):
            yield d
    core = [g["guid"], str(g["linkOrder"]), g["securityFilter"],
            g["serviceAccount"], g["command"]]
    for n in (2, 3):
        for combo in itertools.permutations(core, n):
            for sep in ("|", ":", "-"):
                yield sep.join(combo)
    yield hashlib.sha256(blob).hexdigest()


def try_submit(answer):
    try:
        r = requests.post(BASE + "/submit", json={"answer": answer}, timeout=15)
    except Exception:
        return None
    if r.status_code != 403:
        return r.status_code, answer, r.text[:200]
    return None


# ... (truncated)
```

### Step 2: 2. **Pairwise/triple joins** of those fields with `"" : - / | , space _ ; = @ \`

2. **Pairwise/triple joins** of those fields with `"" : - / | , space _ ; = @ \` — none.

### Step 3: 3. **`safctf{<field>}` wrappers** (incl. dashed guid) — none.

3. **`safctf{<field>}` wrappers** (incl. dashed guid) — none.

## Flag

```
safctf{8a97f3881e4828d37406ed0953ff9573}
```
