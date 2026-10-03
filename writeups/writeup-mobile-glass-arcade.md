---
title: "Glass Arcade"
ctf: "Safaricom CTF"
date: 2026-10-04
category: malware
difficulty: hard
points: 750
flag_format: "safctf{...}"
author: "safaricom-ctf-team"
---

# Glass Arcade

## Summary

Target: http://54.72.82.22:8380 (desk app; `GET /submit` -> 405)

## Solution

### Step 1: Run the solve script:

```python
#!/usr/bin/env python3
"""Glass Arcade (mobile, 300) — decrypt assets/session.bin and grade via /submit.

Scheme (from Lobby.visit(), jadx):
  bArr[i] = CONST[i] ^ transfer_blob[i]        # 16 bytes, from session.json
  key     = SHA-256( bArr || b"glass-arcade/3" )   # Java digest(input) == update+final
  iv      = session.bin[0:12]                  # 12-byte GCM nonce
  pt      = AES-GCM(key, iv).decrypt(session.bin[12:])   # 16-byte tag is the tail
The plaintext is an intermediate; /submit grades it to the real flag.
"""
import base64
import hashlib
import json
import sys

import requests
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

BASE = "http://54.72.82.22:8380"
CONSTS = [
    80 - 0, 188 - 7, 119 - 14, 129 - 21, 216 - 28, 120 - 35, 184 - 42, 214 - 49,
    52 - 56, 215 - 63, 69 - 70, 26 - 77, 20 - 84, 60 - 91, 225 - 98, 175 - 105,
]
BUILD_TAG = b"glass-arcade/3"


def derive_key(transfer_b64: str) -> bytes:
    blob = base64.b64decode(transfer_b64)
    bx = bytes((c & 0xFF) ^ t for c, t in zip(CONSTS, blob))
    return hashlib.sha256(bx + BUILD_TAG).digest()


def decrypt(session_bin: bytes, transfer_b64: str) -> str:
    iv, ct = session_bin[:12], session_bin[12:]
    return AESGCM(derive_key(transfer_b64)).decrypt(iv, ct, None).decode()


def main() -> None:
    base = sys.argv[1] if len(sys.argv) > 1 else BASE
    session = requests.get(f"{base}/downloads/session.json", timeout=30).json()
    blob = requests.get(f"{base}/downloads/glass-arcade.apk", timeout=60).content
    import io
    import zipfile
    session_bin = zipfile.ZipFile(io.BytesIO(blob)).read("assets/session.bin")

    receipt = decrypt(session_bin, session["transfer"])
    print(f"[*] intermediate: {receipt}")
    r = requests.post(f"{base}/submit", json={"answer": receipt}, timeout=30)
    print(f"[*] /submit -> {r.status_code} {r.text}")
    data = r.json()
    if data.get("ok"):
        print(f"[+] FLAG: {data['message']}")


if __name__ == "__main__":
    main()

```

## Flag

```
safctf{318223415bd0e96e2f63b0dd88eacf2d}
```
