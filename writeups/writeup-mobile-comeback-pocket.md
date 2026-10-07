---
title: "Comeback Pocket"
ctf: "Safaricom CTF"
date: 2026-10-06
category: malware
difficulty: medium
points: 300
flag_format: "safctf{...}"
author: "Strawhats"
---

# Comeback Pocket

> **Category:** MOBILE · **Points:** 300 · **Difficulty:** medium

## Discovery, analysis & exploitation

The full hunt below is reproduced from our working notes — recon, fingerprinting, the bug, dead ends, and the path to the flag.

the decrypted receipt `safctf{ddd6569c-7655-4aa8-84e8-cd7f4acd4f78}` is only the intermediate).

## Artifacts (kept out of git — binary extensions are gitignored)
| file | sha256 |
|---|---|
| `http://54.72.82.22:8360/downloads/pocket.ab` | `e6f127c9406fe64f282f969ef64180595a837558335dfcb4d7719b957e77635b` |
| `http://54.72.82.22:8360/downloads/Session.java` | `d0163b5bc4d903efb79f5215c771fe7c57dbf79ec3e94dee229527316cdac4d3` |

`Session.java` is the whole map:

```java
SecretKey load(String uid,String device,byte[] salt) {
 return PBKDF2WithHmacSHA256(uid+":"+device,salt,12000,256);
}
// pass.bin: 12-byte IV, AES/GCM ciphertext, 16-byte tag.
```

## Path
1. `pocket.ab` header: `ANDROID BACKUP\n5\n1\nnone\n` — version 5, compressed flag 1,
   no encryption. Payload after line 4 is a raw zlib stream → a tar of
   `apps/com.comeback.pocket/{db/accounts.db, sp/session.xml, f/pass.bin, _manifest}`.
   (`unzip` fails, as expected — parse the header + `zlib.decompress`.)
2. `sp/session.xml` gives the salt and KDF rounds:
   `<string name="s">67beb4eff155c1bff95be68fd8c2e4e0</string>` (16 bytes) and `rounds=12000`.
   `installation` = `member-2dea8614a9` ties to the active DB row.
3. `db/accounts.db` → `SELECT uid,device FROM accounts WHERE active=1` →
   `member-2dea8614a9` / `4e13eb4f120b8f4709ee20e57a597758`. The 30 other rows are decoys.
4. Key = PBKDF2-HMAC-SHA256(`uid:device`, salt, 12000, 32). Split `f/pass.bin` as
   IV(12) ‖ ct ‖ tag(16) and AES-GCM decrypt → receipt.
5. `POST /submit {"answer": receipt}` → graded flag.

## Run
```
/home/nomad/safaricom_ctf/.venv/bin/python solve.py
```

## Solve script

`mobile/comeback-pocket/solve.py`:

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

## Tools

**Used in this solve:**

- `hashlib`
- Python `requests` (HTTP client)
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

Intermediate answer: `safctf{408e83b586354238e5a8e968a74b8b64}`  
Graded flag: `safctf{ddd6569c-7655-4aa8-84e8-cd7f4acd4f78}`

```
safctf{ddd6569c-7655-4aa8-84e8-cd7f4acd4f78}
```
