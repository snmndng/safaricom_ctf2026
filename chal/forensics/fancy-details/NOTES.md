# Fancy Details — Forensics, 300 pts (SOLVED)

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

## Flag
```
safctf{245ccf0110f6422d41671064cee8da68}
```
No `/submit` endpoint on this desk (nginx returns 404), so the recovered
value is the flag itself.

## Reproduce
`python3 solve.py` (deps: requests, Pillow, pycryptodome)
