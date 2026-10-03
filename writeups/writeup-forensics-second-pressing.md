---
title: "Second Pressing"
ctf: "Safaricom CTF"
date: 2026-10-04
category: forensics
difficulty: medium
points: 500
flag_format: "safctf{...}"
author: "safaricom-ctf-team"
---

# Second Pressing

## Summary

**Target:** http://54.72.82.22:8460 (Werkzeug/Flask)

## Solution

### Step 1: Run the solve script:

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
# ... (truncated)
```

## Flag

```
safctf{12bbc51d-7450-44c6-af3f-1723514b8aad}
```
