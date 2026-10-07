---
title: "Fancy Details"
ctf: "Safaricom CTF"
date: 2026-10-06
category: forensics
difficulty: medium
points: 300
flag_format: "safctf{...}"
author: "Strawhats"
---

# Fancy Details

> **Category:** FORENSICS · **Points:** 300 · **Difficulty:** medium

## Discovery, analysis & exploitation

The full hunt below is reproduced from our working notes — recon, fingerprinting, the bug, dead ends, and the path to the flag.

Desk: `http://54.72.82.22:8210/` ("FRAME / FOUND" photo archive)

## Artifacts
| file | url | sha256 |
|------|-----|--------|
| photo.jpg | `http://54.72.82.22:8210/downloads/photo.jpg` | `a6a6b08199234f8506c4443a0bd1bdedf4c15008edd68c8ecd8fd4e140e7bfe6` |
| archive.tar.gz.enc | `http://54.72.82.22:8210/downloads/archive.tar.gz.enc` | `eda40c41de34c96a73e58c5730205dc30c4022e136bb7bdad66025238b4c3df0` |

(binaries fetched to `artifacts/`, not committed — repo gitignores binary extensions)

## Format
- `photo.jpg` — single clean progressive JPEG 1024x1024, no trailing/appended
  data, no extra DQT/DHT stego, no LSB payload. The image content is an
  AI-generated "folder + play button" illustration; its on-image digits
  (0921 / 0-121 / 0321 / 5 08) are AI noise and are decoys.
- `archive.tar.gz.enc` — 192-byte OpenSSL "Salted__" container
  (`file`: "openssl enc'd data with salted password"), i.e. 8-byte salt +
  176-byte ciphertext.

## The anomaly (the "one detail that doesn't belong")
Hand-crafted EXIF in `photo.jpg`:
```
Artist = "qebjffnc"                 <-- ROT13 of "drowssap"
GPSLatitude  = 52 28 48             <-- decoy
GPSLongitude = 1  53 24             <-- decoy
```
ROT13-decoding `qebjffnc` gives `drowssap`, which reversed is `password`.
That is the passphrase ("a thoughtful touch can change the whole impression"
= the artist tag was text-touched/encoded).

## Decryption
```
openssl enc'd header  : Salted__
cipher                : AES-256-CBC
KDF                   : PBKDF2-HMAC-SHA256, 100000 iterations
passphrase            : password
```
The resulting gzip stream is deliberately truncated (gzip trailer reports a
bogus ISIZE and errors with "unexpected end of file"), but tar still reads the
one stored member: `nested1.tar` -> `flag.txt`.

(Note: the default `openssl enc` on modern OpenSSL uses an EVP_BytesToKey
KDF; this archive uses `-pbkdf2` with 100000 iterations, so plain
`openssl enc -d -aes-256-cbc -k password` fails — Python `hashlib.pbkdf2_hmac`
was needed.)

## Reproduce
`python3 solve.py` (deps: requests, Pillow, pycryptodome)

## Solve script

`forensics/fancy-details/solve.py`:

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

## Tools

**Used in this solve:**

- `hashlib`
- `tarfile`
- Python `requests` (HTTP client)
- PyCryptodome
- Pillow (imaging)
- Python 3 (solver)
- openssl

**Other tools that fit this category:**

- Wireshark / tshark (pcap)
- Volatility 3 (memory)
- binwalk + foremost (carving)
- exiftool (metadata)
- zsteg / StegSolve (image stego)
- The Sleuth Kit / Autopsy (disk)

## Flag

```
safctf{245ccf0110f6422d41671064cee8da68}
```
