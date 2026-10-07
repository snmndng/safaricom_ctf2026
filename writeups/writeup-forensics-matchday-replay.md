---
title: "Matchday Replay"
ctf: "Safaricom CTF"
date: 2026-10-06
category: forensics
difficulty: medium
points: 300
flag_format: "safctf{...}"
author: "Strawhats"
---

# Matchday Replay

> **Category:** FORENSICS · **Points:** 300 · **Difficulty:** medium

## Discovery, analysis & exploitation

The full hunt below is reproduced from our working notes — recon, fingerprinting, the bug, dead ends, and the path to the flag.

- **Target:** `http://54.72.82.22:8450`

## Artefacts

`GET /downloads/replay.zip` (linked from the page; Werkzeug/3.1.9 Python/3.11.16):

| file | size | sha256 |
|---|---|---|
| `replay.zip` | 2145 B | `751ffb079085854f82647cc750840e08fec8c6f7bf9c4c35c2b75af440707964` |
| `capture.pcap` | 3276 B | `59bb226b448b292ed5103a2243ce0ae63ce1820aaaa89dbad0d7c141cd49ebbe` |

`capture.pcap` is `LINKTYPE_USER0` (DLT 147) — **raw payloads, no link layer**, so
`tshark -r` shows no protocols and the usual HTTP/TCP/DNS triage is a dead end.
`capinfos` reports 87 packets, exactly 1 s apart (`ts` = 1800000000 + index).
The zip also ships `session.log`:

```
18:44 volunteers crossed the end line
18:48 lights lowered
19:02 replay card: afterglow-17
```

## The wire format (reverse engineered)

Two ASCII-tagged record types are interleaved in the capture:

```
IDLE : b"IDLE" + 18 random bytes                  x80  (decoy padding)
LIVE : b"LIVE" + seq(2, big-endian)
               + len(2, big-endian) + data(len)   x7
```

LIVE payload lengths: seq 0,1,2,3,4,5 → 7 bytes each, seq 6 → 2 bytes = **44 bytes
total**. The 7 LIVE packets **arrive out of order** — arrival seq order is
`2, 5, 1, 4, 6, 0, 3` — which is the "Replay" of the title.

## The cipher

`session.log`'s `replay card: afterglow-17` is the keystream seed (the "card"
being replayed):

```
K = sha256(b"afterglow-17")
  = dff484c50f1b0f43cfce8740ab2eb769ff419a6e848053e32dcf55b0a09a12fc
```

Each LIVE fragment sits at flag offset `7*seq` and is XORed with **K wrapped
modulo 12** (not the full 32 bytes): fragment byte *i* of packet *seq* uses
`K[(7*seq + i) % 12]`. Concatenating the plaintexts in seq order yields the flag:

```
seq 0 -> safctf{
seq 1 -> 5554fd0
seq 2 -> 0-017a-
seq 3 -> 4915-a8
seq 4 -> 83-a7ef
seq 5 -> 2639f73
seq 6 -> b}
```

which assembles to `safctf{5554fd00-017a-4915-a883-a7ef2639f73b}` — a clean
8-4-4-4-12 UUID-shaped body (only 16 chars of the body are guessable from a single
fragment, so the full string is genuinely recovered by the crypto).

## Submitting

`POST /submit {"answer": "..."}` (`GET` → 405, `Allow: OPTIONS, POST`):

```
{"answer":"safctf{5554fd00-017a-4915-a883-a7ef2639f73b}"}
  -> {"ok": true,  "message": "safctf{e2d6cc7b320577dd3eb54aa08f86e446}"}
{"answer":"hello"}
  -> {"ok": false, "message": "The request could not be completed."}
```

Repeating the correct submission three times returns the same receipt, so the
receipt is the fixed challenge flag.

## Attempts that did NOT work (dead ends)

- `tshark -q -z io,phs` / `--export-objects http` — USER0 raw payloads, nothing to dissect.
- Grepping every payload (LIVE + IDLE) for `safctf` — no plaintext flag on the wire.
- Packet **timing**: uniform 1 s spacing across all 87 packets — no interval encoding.
- Concatenating the 44 LIVE bytes in seq order and XORing with the **full 32-byte**
  `sha256(card)` keystream: the first 12 bytes decode (`safctf{5554f`) and the rest
  is garbage — this is what hid the period-12 wrap for a long while.
- Same with the 80×18-byte IDLE payloads as a keystream source, reversed streams,
  column/strided extraction of IDLE bytes, and packet-order permutations.
- AES-ECB/CBC, RC4, ChaCha20 and single-byte XOR over the 32-byte tail — all noise.
- `AES`/`RC4`/`ChaCha20`/decompress/encoding attempts on the tail — noise.

The decisive step was noticing that individual LIVE fragments decode to
hex/dash strings at *specific* keystream offsets (seq 2 @ 2 → `0-017a-`,
seq 4 @ 4 → `83-a7ef`, seq 6 @ 6 → `b}`), and that the odd-sequence packets only
decode cleanly if the keystream **wraps every 12 bytes** rather than every 32.

## Reproduce

```
python3 chal/forensics/matchday-replay/solve.py
```

Stdlib only; fetches the zip, parses the capture, reconstructs the answer, submits
it, and prints the receipt flag.

## Solve script

`forensics/matchday-replay/solve.py`:

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
        data=json.dumps({"answer": answer}).encode(),
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=30) as r:
        resp = json.loads(r.read().decode())
    print("[+] submit -> %s" % resp)

    flag = resp.get("message") if resp.get("ok") else None
    if flag and flag.startswith("safctf{"):
        print("FLAG: %s" % flag)
    else:
        print("NO FLAG -- submit did not return a receipt")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
```

## Tools

**Used in this solve:**

- `hashlib`
- `struct` (binary parsing)
- Python `urllib` (stdlib HTTP client)
- `zipfile`
- Python 3 (solver)
- Wireshark/tshark

**Other tools that fit this category:**

- Wireshark / tshark (pcap)
- Volatility 3 (memory)
- binwalk + foremost (carving)
- exiftool (metadata)
- zsteg / StegSolve (image stego)
- The Sleuth Kit / Autopsy (disk)

## Flag

Intermediate answer: `safctf{5554fd00-017a-4915-a883-a7ef2639f73b}`  
Graded flag: `safctf{e2d6cc7b320577dd3eb54aa08f86e446}`

```
safctf{e2d6cc7b320577dd3eb54aa08f86e446}
```
