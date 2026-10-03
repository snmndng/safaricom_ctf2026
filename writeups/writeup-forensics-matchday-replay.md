---
title: "Matchday Replay"
ctf: "Safaricom CTF"
date: 2026-10-04
category: forensics
difficulty: medium
points: 300
flag_format: "safctf{...}"
author: "nomadspecter <the.nomad.specter@gmail.com>"
---

# Matchday Replay

## Summary

- **Category:** forensics

## Solution

### Step 1: Run the solve script:

```python
#!/usr/bin/env python3
"""
Matchday Replay (FORENSICS, 300 pts) - solve script.

Fetches http://54.72.82.22:8450/downloads/replay.zip, parses the custom
capture (LINKTYPE_USER0, DLT 147) inside it, reconstructs the answer and
submits it to /submit, printing the receipt (the challenge flag).

Reconstruction:
  * capture.pcap holds two packet types, both raw payloads (no link layer):
      IDLE  : b"IDLE" + 18 random bytes        (padding / decoy)
      LIVE  : b"LIVE" + seq(2,big-endian) + len(2,big-endian) + data(len)
  * The 7 LIVE packets carry 7 bytes each except seq 6 (2 bytes) -> 44 bytes.
  * session.log leaks the keystream seed:  "replay card: afterglow-17"
    keystream K = sha256(b"afterglow-17").digest().
  * The packets arrive out of order (arrival seq order 2,5,1,4,6,0,3 --
    the "replay").  Each LIVE fragment is XORed with K wrapped modulo 12
    (K[p % 12]) and sits at flag offset 7*seq, so the keystream offset for
    fragment byte i of packet seq is (7*seq + i) % 12.
  * Concatenated in seq order the plaintext is
        safctf{5554fd00-017a-4915-a883-a7ef2639f73b}
    (a UUID-shaped body: 8-4-4-4-12).
  * POSTing that answer to /submit returns the receipt, which is the flag.
"""
import hashlib
import io
import json
import re
import struct
import urllib.request
import zipfile

BASE = "http://54.72.82.22:8450"
ZIP_URL = BASE + "/downloads/replay.zip"
KS_PERIOD = 12


def fetch_zip():
    with urllib.request.urlopen(ZIP_URL, timeout=30) as r:
        return r.read()


def parse_pcap(raw):
    """Return {seq: data} for LIVE packets of the custom USER0 capture."""
    magic = raw[:4]
    if magic == b"\xd4\xc3\xb2\xa1":          # little-endian
        end = "<"
    elif magic == b"\xa1\xb2\xc3\xd4":        # big-endian
        end = ">"
    else:
        raise ValueError("unsupported pcap magic %r" % magic)
    off, out = 24, {}
    while off + 16 <= len(raw):
        _ts, _tus, incl, _orig = struct.unpack(end + "IIII", raw[off:off + 16])
        off += 16
        pkt = raw[off:off + incl]
        off += incl
        if pkt[:4] == b"LIVE":
            seq = struct.unpack(">H", pkt[4:6])[0]
            ln = struct.unpack(">H", pkt[6:8])[0]
            out[seq] = pkt[8:8 + ln]
    return out


def main():
    zdata = fetch_zip()
    print("[+] replay.zip %d bytes sha256=%s" % (len(zdata), hashlib.sha256(zdata).hexdigest()))
    zf = zipfile.ZipFile(io.BytesIO(zdata))
    names = zf.namelist()
    print("[+] members: %s" % names)

    pcap_name = next(n for n in names if n.endswith((".pcap", ".pcapng")))
    cap = zf.read(pcap_name)
    print("[+] %s %d bytes sha256=%s" % (pcap_name, len(cap), hashlib.sha256(cap).hexdigest()))

    # card id from session.log -- fall back to the known literal if absent
    card = b"afterglow-17"
    for n in names:
        if n.endswith(".log"):
            m = re.search(rb"replay card:\s*(\S+)", zf.read(n))
            if m:
                card = m.group(1)
    print("[+] keystream card id: %r" % card)
    K = hashlib.sha256(card).digest()

    live = parse_pcap(cap)
    print("[+] LIVE packets by seq: %s" % {s: len(v) for s, v in sorted(live.items())})

    answer = bytearray()
    for seq in sorted(live):
        data = live[seq]
        base = (7 * seq) % KS_PERIOD
        frag = bytes(c ^ K[(base + i) % KS_PERIOD] for i, c in enumerate(data))
        print("    seq %d -> %r" % (seq, frag))
        answer += frag
    answer = answer.decode()
    print("[+] reconstructed answer: %s" % answer)

    req = urllib.request.Request(
        BASE + "/submit",
# ... (truncated)
```

## Flag

```
safctf{5554fd00-017a-4915-a883-a7ef2639f73b}
```
