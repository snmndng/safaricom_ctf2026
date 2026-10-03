---
title: "Signal Garden"
ctf: "Safaricom CTF"
date: 2026-10-04
category: misc
difficulty: medium
points: 300
flag_format: "safctf{...}"
author: "nomadspecter <the.nomad.specter@gmail.com>"
---

# Signal Garden

## Summary

- **Target:** http://54.72.82.22:8650 (Werkzeug / Python — desk app)

## Solution

### Step 1: Run the solve script:

```python
#!/usr/bin/env python3
"""Signal Garden (8650) -- FSK two-tone audio carrying a framed Base32 payload.

Desk app: GET / links /downloads/session.zip, which holds
`take.wav` (8 kHz mono s16, 5.84 s) and `desk.json`.
`POST /submit` is a decoy (403 for every answer -- the family runtime's
`answer_hash` fallback `'!'` never matches, see chal/_shared/organizer-service.py).
The flag is inside the audio.

The WAV is an exact sum of pure-sine runs, unit = 80 samples = 10 ms:

  * two tones only -- 1000 Hz (bit 0) and 2000 Hz (bit 1), amplitude +/-12000,
    every run starting at phase 0, so reconstruction from the run model is
    bit-exact (max abs diff 0): the *entire* payload is the run lengths;
  * 385 runs, strictly alternating tone, lengths 1..5 units -> RLE expansion to
    584 bits (5.84 s / 10 ms = 584).

The bitstream is then:

  bits[0:16]  = 1010101001010101 = AA 55        (16-bit sync)
  bits[16:]   = 71 frames of [marker][7 data bits]

and the marker bit alternates 0,1,0,1,... (equivalently: after the sync, the MSB
of byte k is k & 1). Complementing the odd frames makes all 71 bytes land in the
Base32 alphabet; 71 chars + one '=' pad is a legal Base32 length (44 bytes).

    ONQWMY3UMZ5TIZJZMY2WKOBTFU2WGMZSFU2DINBUFU4DMNDFFU3WCZLDGNTGIODFMNRTM7I
    -> safctf{4e9f5e83-5c32-4444-864e-7aec3fd8ecc6}

Run:  /home/nomad/safaricom_ctf/.venv/bin/python solve.py
"""
import base64
import io
import zipfile

import numpy as np
import requests

BASE = "http://54.72.82.22:8650"
SYNC = (0xAA, 0x55)


def download():
    """Fetch the desk archive; take.wav is the payload."""
    r = requests.get(BASE + "/downloads/session.zip", timeout=30)
    r.raise_for_status()
    return zipfile.ZipFile(io.BytesIO(r.content))


def tone_runs(samples, unit=80):
    """Split into runs of a single tone; return [(bit, length_in_units)].

    A pure sine has s[i] + s[i+2] = 2*cos(w)*s[i+1], so cos(w) separates the two
    tones (w = 2*pi*f/8000 -> 0.7071 at 1000 Hz, 0.0 at 2000 Hz) with no FFT.
    """
    s = samples.astype(np.int64).astype(float)
    mid = s[1:-1]
    good = np.abs(mid) > 1000
    cosw = np.zeros(len(s) - 2)
    cosw[good] = (s[:-2][good] + s[2:][good]) / (2 * mid[good])
    tone = np.where(cosw > 0.35, 0, 1).astype(np.int8)  # 0 = 1000 Hz, 1 = 2000 Hz
    tone = np.concatenate([[tone[0]], tone, [tone[-1]]])
    # every run is a whole number of 10 ms units, so each 80-sample block is pure:
    # classify per block by majority vote, then merge equal neighbours into runs.
    nb = len(tone) // unit
    vote = (tone[:nb * unit].reshape(nb, unit).mean(axis=1) > 0.5).astype(int)
    idx = np.flatnonzero(np.diff(vote)) + 1
    bounds = np.concatenate([[0], idx, [nb]])
    return [(int(vote[a]), int(b - a)) for a, b in zip(bounds[:-1], bounds[1:])]


def wav_bits(z):
    import wave

    w = wave.open(io.BytesIO(z.read("take.wav")), "rb")
    assert (w.getnchannels(), w.getsampwidth(), w.getframerate()) == (1, 2, 8000)
    samples = np.frombuffer(w.readframes(w.getnframes()), dtype=np.int16)
    runs = tone_runs(samples)
    return "".join(str(t) * n for t, n in runs)


def decode(bitstr):
    by = bytes(int(bitstr[i:i + 8], 2) for i in range(0, len(bitstr) // 8 * 8, 8))
    assert by[:2] == bytes(SYNC), "missing AA55 sync"
    # per-frame polarity: complement the odd-indexed frames
    body = bytes(c if i % 2 == 0 else (~c) & 0xFF for i, c in enumerate(by[2:]))
    return base64.b32decode(body.decode() + "=").decode()


def main():
    bits = wav_bits(download())
    print("bits", len(bits), "runs", sum(1 for a, b in zip(bits, bits[1:]) if a != b) + 1)
    flag = decode(bits)
    print("flag:", flag)
    # /submit is a decoy here; the flag above is the graded one.
    r = requests.post(BASE + "/submit", json={"answer": flag}, timeout=20)
    print("POST /submit ->", r.status_code, r.text[:120])


if __name__ == "__main__":
# ... (truncated)
```

## Flag

```
safctf{4e9f5e83-5c32-4444-864e-7aec3fd8ecc6}
```
