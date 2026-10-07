---
title: "Second Pressing"
ctf: "Safaricom CTF"
date: 2026-10-06
category: forensics
difficulty: medium
points: 500
flag_format: "safctf{...}"
author: "Strawhats"
---

# Second Pressing

> **Category:** FORENSICS · **Points:** 500 · **Difficulty:** medium

## Discovery, analysis & exploitation

The full hunt below is reproduced from our working notes — recon, fingerprinting, the bug, dead ends, and the path to the flag.

**Target:** http://54.72.82.22:8460 (Werkzeug/Flask)

## Artifact

- Download page: `/` → links `/downloads/listening-room.zip`
- `http://54.72.82.22:8460/downloads/listening-room.zip`
- size 1034 bytes
- sha256 `d3e482840703c654072a102216e23d694c0230b09c79c5da6b58ccc8e2a95f82`
  (kept out of git per repo `.gitignore`)

Zip members (mode `-rw------- `, mtimes 2026-10-01 03:59):

| file | what |
|---|---|
| `library.db` | SQLite 3 DB, page size 4096, 2 pages, schema `CREATE TABLE pressings(id INTEGER PRIMARY KEY,title TEXT,receipt TEXT)` |
| `library.db-wal` | SQLite Write-Ahead Log, 8272 bytes, 2 frames, both page 2 |
| `library.db-shm` | WAL shared-memory index (red herring here) |
| `desk.log` | `16:41 test pressing queued` / `16:42 catalogue revised` / `16:43 counter closed` |

## Story / hypothesis

"Second Pressing" = a re-cut of a record. The catalogue row was **re-cut**
(overwritten) after the first pressing: `desk.log` says the catalogue was
"revised" at 16:42. Because SQLite was in **WAL mode**, the pre-revision page
was flushed to the WAL as a committed frame; the revision then wrote a newer
frame of the same page, truncating the `receipt` column down to the literal
string `withdrawn`. The original, intact `receipt` (a base64/zlib blob) is
therefore still sitting in the *older* WAL frame.

The landing page script also exposes a `/submit` endpoint taking
`{"answer": ...}` and hints: "Keep your collection receipt when your visit is
complete." So the recovered receipt is the answer key.

## Technique — SQLite WAL forensics

WAL layout: 32-byte header (`magic=0x377f0682`, page size 4096) followed by
frames of `24 + 4096` bytes; each frame header is `pgno (u32), commit (u32),
salt1, salt2, cksum1, cksum2`.

Both frames target page 2. Decoding page 2 of each frame:

- frame 0 (older): `Test pressing` + `eJwrTkxLLkmrNjRKSko2NUzRNTcxNdA1MUk2001MM07TNTQ3MjY1NEmySExMqQUALKEM0A==`
- frame 1 (newer): `Test pressing` + the same base64 truncated to 48 chars, then `Test pressingwithdrawn`

The base64 column value is glued to its label with no separator, so a naive
base64 decode fails; sliding the start offset and letting zlib's integrity
check reject the wrong alignments recovers it:

```
base64 → zlib.decompress → b'safctf{12bbc51d-7450-44c6-af3f-1723514b8aad}'
```

That UUID is the **collection receipt**. It is NOT the final flag — it is the
`answer` the app wants. POST it to `/submit`:

```
$ curl -s -X POST http://54.72.82.22:8460/submit \
      -H 'Content-Type: application/json' \
      -d '{"answer":"safctf{12bbc51d-7450-44c6-af3f-1723514b8aad}"}'
{"message":"safctf{34a793a0d11032abb97236fafc9b30c4}","ok":true}
```

A wrong answer (`{"answer":"nope"}`) returns `{"message":"The request could not
be completed.","ok":false}`, confirming the receipt is the required key.

## Repro

`python3 solve.py` — fetches the zip, parses the WAL, recovers the receipt,
submits it, prints the flag. Verified reproducible.

## Solve script

`forensics/second-pressing/solve.py`:

```python
#!/usr/bin/env python3
"""
Second Pressing (FORENSICS, 500 pts) - Safaricom CTF
====================================================

Artifact: http://54.72.82.22:8460/downloads/listening-room.zip
  library.db, library.db-wal, library.db-shm, desk.log
  sha256(listening-room.zip) = d3e482840703c654072a102216e23d694c0230b09c79c5da6b58ccc8e2a95f82

Technique: SQLite WAL (Write-Ahead Log) forensics.
  The "second pressing" (a re-cut record) OVERWROTE the original catalogue
  row in a live SQLite DB.  The committed DB page in the WAL holds the older
  version of the row, which still contains the original base64/zlib "receipt".
  The newer WAL frame truncated that column to the literal string "withdrawn".

  Recover the receipt -> POST it to /submit -> the app returns the flag.

Run:  python3 solve.py
"""

import base64
import io
import json
import re
import struct
import urllib.request
import zipfile
import zlib

BASE = "http://54.72.82.22:8460"
ZIP_URL = BASE + "/downloads/listening-room.zip"
SUBMIT_URL = BASE + "/submit"


def fetch(url: str) -> bytes:
    with urllib.request.urlopen(url, timeout=60) as r:
        return r.read()


def printable_runs(blob: bytes, minlen: int = 3):
    return re.findall(rb"[ -~]{%d,}" % minlen, blob)


def parse_wal_frames(wal: bytes):
    """Yield (frame_index, pgno, page_body) for every complete frame in a WAL."""
    magic, ver, psz, cks = struct.unpack(">IIII", wal[:16])
    if magic not in (0x377F0682, 0x377F0683):
        raise ValueError("not a SQLite WAL")
    frame_size = psz + 24
    n = (len(wal) - 32) // frame_size
    for i in range(n):
        off = 32 + i * frame_size
        pgno, commit = struct.unpack(">II", wal[off:off + 8])
        body = wal[off + 24: off + 24 + psz]
        yield i, pgno, body


B64_CHARS = set(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=")


def _try_zlib_b64(cand: bytes):
    cand = cand.rstrip(b"=")
    if len(cand) < 8:
        return None
    padded = cand + b"=" * (-len(cand) % 4)
    try:
        dec = zlib.decompress(base64.b64decode(padded, validate=True))
    except Exception:
        return None
    return dec


def recover_receipt(wal: bytes):
    """
    The older WAL frame stores the receipt as a base64/zlib column value that is
    glued to a text label ("Test pressing<base64>").  Try every offset inside
    each printable run so the label prefix does not poison the base64 decode.
    """
    for _, _, body in parse_wal_frames(wal):
        for run in printable_runs(body, minlen=16):
            # The receipt column value is glued to a text label with no
            # separator ("Test pressing<base64>").  Slide the start offset and
            # let zlib's integrity check reject every wrong alignment.
            for i in range(len(run)):
                cand = bytes(c for c in run[i:] if c in B64_CHARS)
                dec = _try_zlib_b64(cand)
                if not dec:
                    continue
                text = dec.decode("utf-8", "replace")
                print("      [decoded WAL blob] %r" % text[:200])
                mm = re.search(r"safctf\{[0-9a-fA-F-]{32,36}\}", text)
                if mm:
                    return mm.group(0)
    return None


def submit(answer: str) -> str:
    data = json.dumps({"answer": answer}).encode()
    req = urllib.request.Request(
        SUBMIT_URL, data=data,
        headers={"Content-Type": "application/json"}, method="POST",
    )
    with urllib.request.urlopen(req, timeout=30) as r:
        return r.read().decode()


def main():
    print("[*] fetching", ZIP_URL)
    zbytes = fetch(ZIP_URL)
    print("[*] zip size:", len(zbytes))

    zf = zipfile.ZipFile(io.BytesIO(zbytes))
    names = zf.namelist()
    print("[*] members:", names)

    wal = zf.read("library.db-wal")
    print("[*] wal size:", len(wal))

    print("[*] desk.log:")
    for line in zf.read("desk.log").decode(errors="replace").splitlines():
        print("      " + line)

    receipt = recover_receipt(wal)
    if not receipt:
        raise SystemExit("[-] no receipt found in WAL")
    print("[+] recovered receipt (WAL older frame):", receipt)

    resp = submit(receipt)
    print("[*] /submit response:", resp)

    m = re.search(r"safctf\{[0-9a-f]{32}\}", resp)
    if not m:
        raise SystemExit("[-] flag not present in submit response")
    print("\nFLAG:", m.group(0))


if __name__ == "__main__":
    main()
```

## Tools

**Used in this solve:**

- `base64`
- `struct` (binary parsing)
- Python `urllib` (stdlib HTTP client)
- `zipfile`
- Python 3 (solver)
- curl

**Other tools that fit this category:**

- Wireshark / tshark (pcap)
- Volatility 3 (memory)
- binwalk + foremost (carving)
- exiftool (metadata)
- zsteg / StegSolve (image stego)
- The Sleuth Kit / Autopsy (disk)

## Flag

Intermediate answer: `safctf{12bbc51d-7450-44c6-af3f-1723514b8aad}`  
Graded flag: `safctf{34a793a0d11032abb97236fafc9b30c4}`

```
safctf{34a793a0d11032abb97236fafc9b30c4}
```
