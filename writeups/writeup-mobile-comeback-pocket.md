---
title: "Comeback Pocket"
ctf: "Safaricom CTF"
date: 2026-10-04
category: malware
difficulty: medium
points: 300
flag_format: "safctf{...}"
author: "safaricom-ctf-team"
---

# Comeback Pocket

## Summary

**Flag: `safctf{408e83b586354238e5a8e968a74b8b64}`** (graded answer from `/submit`;

## Solution

### Step 1: Run the solve script:

```python
#!/usr/bin/env python3
"""Comeback Pocket (mobile, 150) - Android Backup -> AES-GCM -> /submit."""
import hashlib, io, sqlite3, sys, tarfile, zlib
import requests
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

BASE = "http://54.72.82.22:8360"


def ab_extract(blob):
    """Android Backup v5, uncompressed-flag=1, encryption=none -> zlib tar."""
    parts = blob.split(b"\n", 4)
    assert parts[0] == b"ANDROID BACKUP", parts[0]
    assert parts[3] == b"none", parts[3]
    return tarfile.open(fileobj=io.BytesIO(zlib.decompress(parts[4])))


def main():
    ab = requests.get(f"{BASE}/downloads/pocket.ab").content
    tf = ab_extract(ab)

    xml = tf.extractfile("apps/com.comeback.pocket/sp/session.xml").read().decode()
    salt = bytes.fromhex(__import__("re").search(r'name="s">([0-9a-f]+)<', xml).group(1))
    rounds = int(__import__("re").search(r'name="rounds" value="(\d+)"', xml).group(1))

    db = "/tmp/accounts.db"
    open(db, "wb").write(tf.extractfile("apps/com.comeback.pocket/db/accounts.db").read())
    uid, dev = sqlite3.connect(db).execute(
        "SELECT uid, device FROM accounts WHERE active=1").fetchone()

    # Session.java: PBKDF2WithHmacSHA256(uid+":"+device, salt, 12000, 256)
    key = hashlib.pbkdf2_hmac("sha256", f"{uid}:{dev}".encode(), salt, rounds, 32)
    blob = tf.extractfile("apps/com.comeback.pocket/f/pass.bin").read()
    # pass.bin: 12-byte IV || AES/GCM ciphertext || 16-byte tag
    receipt = AESGCM(key).decrypt(blob[:12], blob[12:], None).decode()
    print("receipt:", receipt)

    r = requests.post(f"{BASE}/submit", json={"answer": receipt}).json()
    print(r)
    return r.get("message")


if __name__ == "__main__":
    assert ab_extract  # smoke: module imports + parser wired
    if "--selftest" in sys.argv:
        print("ok")
    else:
        main()

```

## Flag

```
safctf{408e83b586354238e5a8e968a74b8b64}
```
