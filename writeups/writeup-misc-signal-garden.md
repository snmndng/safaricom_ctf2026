---
title: "Signal Garden"
ctf: "Safaricom CTF"
date: 2026-10-06
category: misc
difficulty: medium
points: 300
flag_format: "safctf{...}"
author: "Strawhats"
---

# Signal Garden

> **Category:** MISC · **Points:** 300 · **Difficulty:** medium

## Discovery, analysis & exploitation

The full hunt below is reproduced from our working notes — recon, fingerprinting, the bug, dead ends, and the path to the flag.

- **Target:** http://54.72.82.22:8650 (Werkzeug / Python — desk app)
- **Blurb:** "Leave a little room between the notes." / header `AMBIENT MUSIC`

## Surface

| Route | Behaviour |
| --- | --- |
| `GET /` | desk page linking `/downloads/session.zip`; renders an answer form that POSTs `/submit` |
| `GET /downloads/session.zip` | 1226 B zip: `take.wav` (93484 B) + `desk.json`, both `2026-10-01 03:59:42`, no extra fields, no comment |
| `GET /health` | `{"status":"ok"}` |
| `POST /submit` | **decoy** — 403 `{"message":"The request could not be completed."}` for *every* answer (the family runtime's `cfg.get('answer_hash','!')` fallback can never match; see `chal/_shared/organizer-service.py`). The flag is in the artifact. |

`desk.json` = `{"session":"take-17","gain_db":-6,"local_start":"23:58","room":"north garden"}`
(the -6 dB is real: amplitude 12000 = 24000/2, i.e. 6.02 dB below the generator's full scale).

The page also ships a client-side "console" that `fetch`es an arbitrary local path
(`if(!path.startsWith('/')||path.startsWith('//'))throw Error('Use a local service path.')`).
Purely a client-side convenience — equivalent to curl; it hid nothing.

## The signal

`take.wav` is 8 kHz / mono / s16, 46720 frames = 5.84 s, only `fmt ` + `data` chunks.
It is an **exact** sum of pure-sine runs: two tones only, 1000 Hz (bit 0) and
2000 Hz (bit 1), an octave apart, amplitude ±12000, every run starting at phase 0.
Rebuilding the waveform from `(tone, length)` makes it bit-exact (max abs diff 0),
so **the whole payload is the run lengths** — there is no sample-level stego.

Unit = 80 samples = 10 ms; 5.84 s / 10 ms = **584 bit slots**. 385 runs, strictly
alternating tone, lengths 1–5 (1:249, 2:90, 3:32, 4:11, 5:3 — RLE of a
random-looking bitstream). Expanding gives 584 bits:

```
1010101001010101 0100111110110001 ...      = aa 55 4f b1 51 a8 4d a6 33 aa 4d a5 ...
```

## The framing (the actual puzzle)

- `bits[0:16] = 1010101001010101 = AA 55` — 16-bit sync.
- The remaining 568 bits are **71 frames of `[marker][7 data bits]`**, and the
  marker bit is *exactly* `k & 1` — it alternates 0,1,0,1,… across all 71 frames
  (equivalently: after the sync, byte *k* has MSB `k & 1`). Probability of that by
  chance ≈ 2⁻⁷⁰.
- So the bytes alternate polarity. **Complementing the odd-indexed frames** turns
  all 71 bytes into Base32 characters (`A–Z2–7`):

```
ONQWMY3UMZ5TIZJZMY2WKOBTFU2WGMZSFU2DINBUFU4DMNDFFU3WCZLDGNTGIODFMNRTM7I
```

71 chars is a legal Base32 length (7 chars in the final block → pad one `=`):

```python
base64.b32decode(s + "=")  ->  b'safctf{4e9f5e83-5c32-4444-864e-7aec3fd8ecc6}'
```

## Reproduce

```
/home/nomad/safaricom_ctf/.venv/bin/python solve.py
```

→ `bits 584 runs 385` / `flag: safctf{4e9f5e83-5c32-4444-864e-7aec3fd8ecc6}`

`solve.py` re-downloads the zip and does the whole chain with numpy only (tone
decision from `s[i]+s[i+2] = 2·cos(w)·s[i+1]`, majority vote per 80-sample block),
so it is self-contained and does not depend on the cached `/tmp` artifacts.

## Notes / what was ruled out

- **The leaked family runtime does not explain this app**: `chal/_shared/organizer-service.py`
  has 13 `kind`s and **no audio kind** (grep for `wav|signal|audio|tone|freq|fft|sample`
  only hits the k8s `spec` lines), so 8650 is either an unknown kind or a bespoke app.
  Its `/submit` still 403s by the same `answer_hash='!'` fallback as the family decoys.
- Ruled out (all English-scored where applicable): Morse (full mark/dash/letter/word
  threshold sweep), Manchester, UART/async-serial framing at 8N1/8E1/8O1, PSK/ASK,
  hidden WAV chunks, extra zip members, Polybius, base-4/5/6 conversions of the run
  lengths, 3-symbol digit grouping, base32/64 alphabet remaps × widths 4–8 × all
  offsets × both bit orders, English-scored XOR/add/sub 0–127, affine `a·v+b mod 128`
  over the 7-bit values, index-dependent `v±k·i` / `v^k·i`, Gray code, base-128
  big-int, plaintext needles (`safctf{`, `flag{`, `ctf{`), differential/NRZI, and
  moving the dropped "marker" bit to each of the 8 frame positions.
- The tell that broke it: with the marker bits dropped the 7-bit values are
  arbitrary (37–90, mixed punctuation), but **complementing the odd frames** makes
  every byte fall inside the 32-character Base32 alphabet — that is not a
  coincidence, it is the author's polarity flag.

## Solve script

`misc/signal-garden/solve.py`:

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
    main()
```

## Tools

**Used in this solve:**

- `base64`
- `zipfile`
- NumPy
- Python `requests` (HTTP client)
- Python 3 (solver)
- curl

**Other tools that fit this category:**

- CyberChef (encoding chains)
- z3 / SageMath (constraints)
- pwntools (interaction)
- Ciphey (auto-decode)

## Flag

```
safctf{4e9f5e83-5c32-4444-864e-7aec3fd8ecc6}
```
