---
title: "Northern Lights"
ctf: "Safaricom CTF"
date: 2026-10-06
category: malware
difficulty: hard
points: 500
flag_format: "safctf{...}"
author: "Strawhats"
---

# Northern Lights

> **Category:** MOBILE · **Points:** 500 · **Difficulty:** hard

## Discovery, analysis & exploitation

The full hunt below is reproduced from our working notes — recon, fingerprinting, the bug, dead ends, and the path to the flag.

Target: http://54.72.82.22:8370 (desk app; `POST /submit {"answer": ...}`)

## Artifact
- `/downloads/device-export.zip`
- sha256 `dd8be3c21cee82782b306d66353b45d5634578f95918b13d64996c157fdf5d86`
- Contents: `Manifest.db` (iOS backup manifest, SQLite), `Keychain.plist`,
  `Library/Preferences/com.northern.lights.plist`, `Persistence.swift`,
  `d4/d443ff447a8bfaa462b13d797ce4b9ad0142c607` (encrypted payload, 72 bytes).

## Scheme (documented in Persistence.swift)
```
key  = PBKDF2-SHA256(keychain.v_Data + UTF8(prefs.account), prefs.salt, prefs.iterations, 32)
blob = nonce[12] || AES.GCM.sealed || tag[16]
```

## Solving
- `Keychain.plist` has 13 items: **12 decoys** with `svce = preview`, and **one live**
  item with `svce = com.northern.lights`, `acct = 18485ad7d74ed05fad7e518b`.
- Prefs: `account = 18485ad7d74ed05fad7e518b` (matches the live item),
  `iterations = 24000`, `salt = 00078d28e71f06971f45d914a5bb3387`.
- Only the live keychain row's `v_Data` + that account derives a key that
  authenticates the GCM blob. Decoys fail the tag check.
- Blob splits: nonce = first 12 bytes, ciphertext+tag = remaining 60 bytes.

## Solve script

`mobile/northern-lights/solve.py`:

```python
#!/usr/bin/env python3
"""Northern Lights (mobile, 200) — iOS backup export -> AES-GCM decrypt -> /submit.

Shape: iOS device export (Manifest.db + Keychain.plist + app prefs plist).
  Persistence.swift documents the scheme:
    key = PBKDF2-SHA256(keychain.v_Data + UTF8(prefs.account), prefs.salt, prefs.iterations, 32)
    blob = nonce[12] || AES.GCM.sealed || tag[16]
  Keychain.plist holds 12 decoy 'preview' items plus the one live
  'com.northern.lights' item whose acct matches prefs.account. Only that
  pair decrypts d4/d443ff447a8bfaa462b13d797ce4b9ad0142c607.
"""
import binascii
import io
import json
import plistlib
import urllib.request
import zipfile

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

BASE = "http://54.72.82.22:8370"
ZIP = BASE + "/downloads/device-export.zip"
# relativePath of the encrypted payload inside the export
BLOB = "d4/d443ff447a8bfaa462b13d797ce4b9ad0142c607"
SALT = None  # taken from the prefs plist


def derive(v_data: bytes, account: str, salt: bytes, iterations: int) -> bytes:
    return PBKDF2HMAC(
        algorithm=hashes.SHA256(), length=32, salt=salt, iterations=iterations
    ).derive(v_data + account.encode())


def main():
    data = urllib.request.urlopen(ZIP).read()
    z = zipfile.ZipFile(io.BytesIO(data))

    prefs = plistlib.loads(z.read("Library/Preferences/com.northern.lights.plist"))
    account = prefs["account"]
    salt = bytes(prefs["salt"])
    iterations = prefs["iterations"]

    items = plistlib.loads(z.read("Keychain.plist"))["items"]
    blob = z.read(BLOB)
    nonce, ct = blob[:12], blob[12:]

    # Only the keychain row whose acct equals prefs.account (and is not a decoy
    # 'preview' entry) yields a key that authenticates under GCM.
    answer = None
    for it in items:
        if it["acct"] != account:
            continue
        key = derive(bytes(it["v_Data"]), account, salt, iterations)
        answer = AESGCM(key).decrypt(nonce, ct, None).decode()
    assert answer, "no keychain row matched prefs.account"

    req = urllib.request.Request(
        BASE + "/submit",
        data=json.dumps({"answer": answer}).encode(),
        headers={"Content-Type": "application/json"},
    )
    print(json.loads(urllib.request.urlopen(req).read()))


if __name__ == "__main__":
    main()
```

## Tools

**Used in this solve:**

- `plistlib`
- Python `urllib` (stdlib HTTP client)
- `zipfile`
- `cryptography` (AEAD/AES)
- Python 3 (solver)

**Other tools that fit this category:**

- jadx / jadx-gui (DEX -> Java)
- apktool (resources + smali)
- Frida + objection (runtime hooking)
- dex2jar + JD-GUI
- adb (device/backup)
- keytool / apksigner

## Flag

Intermediate answer: `safctf{3fd96340be891c629f7e3f3a42202743}`  
Graded flag: `safctf{5068e894-3542-4574-ad65-1a5bfddd75eb}`

```
safctf{5068e894-3542-4574-ad65-1a5bfddd75eb}
```
