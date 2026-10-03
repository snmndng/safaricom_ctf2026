---
title: "Fancy Details"
ctf: "Safaricom CTF"
date: 2026-10-04
category: forensics
difficulty: medium
points: 300
flag_format: "safctf{...}"
author: "Strawhats"
---

# Fancy Details

## Summary

Desk: `http://54.72.82.22:8210/` ("FRAME / FOUND" photo archive)

## Solution

### Step 1: Run the solve script:

```python
#!/usr/bin/env python3
"""Fancy Details — Safaricom CTF (Forensics, 300 pts).

Desk: http://54.72.82.22:8210/

Chain:
  1. /downloads/photo.jpg carries hand-crafted EXIF. The Artist tag is
     ROT13-encoded text: "qebjffnc" -> "drowssap" -> reversed -> "password".
     (The GPS tag 52 28 48 / 1 53 24 is a decoy.)
  2. /downloads/archive.tar.gz.enc is an OpenSSL "Salted__" blob.
     Cipher: AES-256-CBC, KDF: PBKDF2-HMAC-SHA256, 100000 iterations,
     passphrase: "password".
  3. Decrypt -> gzip -> nested1.tar -> flag.txt

Run:  python3 solve.py            # downloads artifacts if missing
Deps: pycryptodome (Crypto), Pillow
"""
import hashlib
import io
import os
import sys
import tarfile

import requests
from Crypto.Cipher import AES
from PIL import Image

BASE = os.path.dirname(os.path.abspath(__file__))
ART = os.path.join(BASE, "artifacts")
URL = "http://54.72.82.22:8210"
os.makedirs(ART, exist_ok=True)


def fetch(name):
    path = os.path.join(ART, name)
    if not os.path.exists(path):
        r = requests.get("%s/downloads/%s" % (URL, name), timeout=30)
        r.raise_for_status()
        with open(path, "wb") as f:
            f.write(r.content)
    return path


def exif_password(jpg_path):
    """Artist tag is ROT13; decode then reverse to get the passphrase."""
    artist = Image.open(jpg_path).getexif().get(0x013B)  # Artist
    import codecs
    return codecs.decode(artist, "rot_13")[::-1]


def openssl_decrypt(blob, password):
    """OpenSSL 'Salted__' container: PBKDF2-HMAC-SHA256(100000) + AES-256-CBC."""
    assert blob[:8] == b"Salted__", "not an openssl salted blob"
    salt, ct = blob[8:16], blob[16:]
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 100000, 48)
    return AES.new(dk[:32], AES.MODE_CBC, dk[32:48]).decrypt(ct)


def main():
    jpg = fetch("photo.jpg")
    enc = fetch("archive.tar.gz.enc")

    pw = exif_password(jpg)
    print("[*] EXIF Artist -> ROT13 -> reverse = %r" % pw)

    tar_gz = openssl_decrypt(open(enc, "rb").read(), pw)
    print("[*] decrypted %d bytes, gzip magic = %s" % (len(tar_gz), tar_gz[:2].hex()))

    # gzip stream is truncated by design; tar still yields the single member.
    with tarfile.open(fileobj=io.BytesIO(tar_gz), mode="r:gz") as tf:
        nested = tf.extractfile(tf.getmembers()[0]).read()

    with tarfile.open(fileobj=io.BytesIO(nested), mode="r:") as tf:
        flag = tf.extractfile("flag.txt").read().decode().strip()

    print("[+] FLAG: %s" % flag)
    return flag


if __name__ == "__main__":
    main()

```

## Flag

```
safctf{245ccf0110f6422d41671064cee8da68}
```
