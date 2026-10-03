---
title: "No Strings Attached"
ctf: "Safaricom CTF"
date: 2026-10-04
category: malware
difficulty: medium
points: 300
flag_format: "safctf{...}"
author: "nomadspecter <the.nomad.specter@gmail.com>"
---

# No Strings Attached

## Summary

`backup.zip` is **not** an `.ab` backup — it is a **full Android Studio project source tree**

## Solution

### Step 1: `backup.zip` is **not** an `.ab` backup — it is a **full Android Studio project 

```python
#!/usr/bin/env python3
"""No Strings Attached (MOBILE, 300) -- safCTF.

GET / links /backup.zip, which is a full Android Studio source tree for the
"SafCTF" app. The blurb ("an archived release note describes a recovery screen
that may not exist in this build") is literal: the flag sits in
res/values/archive.xml -- an orphaned resource file NOT referenced by a single
.kt/.xml in the shipped build. "No strings attached" = the string is in the
resources though no code ever reads it.

Run:  /home/nomad/safaricom_ctf/.venv/bin/python solve.py
"""
import hashlib
import io
import re
import sys
import zipfile
from urllib.request import urlopen

BASE = "http://54.72.82.22:8130"
EXPECTED_SHA256 = "49274b8baa4bd176f3575757c6d82356836ba40eb29d1711a06140a7df7a4688"
FLAG_RE = re.compile(rb"safctf\{[0-9a-fA-F-]{8,}\}")


def fetch(url: str) -> bytes:
    with urlopen(url, timeout=30) as r:
        return r.read()


def main() -> int:
    print(f"[*] GET {BASE}/backup.zip")
    blob = fetch(f"{BASE}/backup.zip")
    sha = hashlib.sha256(blob).hexdigest()
    print(f"[*] {len(blob)} bytes, sha256={sha}")
    assert sha == EXPECTED_SHA256, f"backup changed: {sha}"

    flags = set()
    with zipfile.ZipFile(io.BytesIO(blob)) as z:
        names = z.namelist()
        # The point of the challenge: the flag lives in a resource that the
        # shipped Kotlin never references. Dump any resource file whose name
        # hints at an archive/recovery/legacy screen, plus a full-tree grep.
        for n in names:
            if "/res/values/" in n and n.endswith(".xml"):
                print(f"    res: {n}")
        for n in names:
            if n.endswith((".xml", ".kt", ".java", ".txt", ".gradle", "README")):
                for m in FLAG_RE.findall(z.read(n)):
                    flag = m.decode()
                    flags.add(flag)
                    print(f"[+] {flag}  <- {n}")

    if not flags:
        print("[-] no flag found")
        return 1
    assert len(flags) == 1, f"ambiguous: {flags}"
    print(f"\n[=] FLAG: {flags.pop()}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

```

### Step 2: - `AndroidManifest.xml`: only the standard `MainActivity`; no hidden/non-exporte

- `AndroidManifest.xml`: only the standard `MainActivity`; no hidden/non-exported recovery activity.
- `strings.xml`: normal nav strings (`menu_home`/`menu_gallery`/`menu_slideshow`), one decoy line
  `your_are_here_for_the_safCTF`. No flag.
- Kotlin sources (`MainActivity.kt`, three destination fragments/viewmodels) are unmodified
  Android Studio "Navigation Drawer Activity" boilerplate; no crypto/decoding to reverse.
- `build/`, `.gradle/`, `.idea/` hold no flag.

### Step 3: - `AndroidManifest.xml`: only the standard `MainActivity`; no hidden/non-exporte

- `AndroidManifest.xml`: only the standard `MainActivity`; no hidden/non-exported recovery activity.
- `strings.xml`: normal nav strings (`menu_home`/`menu_gallery`/`menu_slideshow`), one decoy line
  `your_are_here_for_the_safCTF`. No flag.
- Kotlin sources (`MainActivity.kt`, three destination fragments/viewmodels) are unmodified
  Android Studio "Navigation Drawer Activity" boilerplate; no crypto/decoding to reverse.
- `build/`, `.gradle/`, `.idea/` hold no flag.

## Flag

```
safctf{94f40cc66658c67503a859cf383c7622}
```
