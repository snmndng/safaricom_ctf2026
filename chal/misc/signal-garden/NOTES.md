# Signal Garden — MISC, 8650

- **Target:** http://54.72.82.22:8650 (Werkzeug / Python — desk app)
- **Status:** ✅ SOLVED — flag `safctf{4e9f5e83-5c32-4444-864e-7aec3fd8ecc6}`
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
