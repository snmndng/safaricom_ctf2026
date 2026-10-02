# Long Exposure

- **Category:** forensics
- **Points:** 350 (board list says 750)
- **Branch:** `chal/forensics-long-exposure`
- **Target:** `http://54.72.82.22:8470` (Werkzeug / Python)
- **Status:** ❌ UNSOLVED (best-effort solve script + full trail below)

Blurb: *"Some moments belong to the blue hour."* — page title **Long Exposure**,
eyebrow "An ordinary day / A different story", footer "Long Exposure · Open for
the evening", tagline "PHOTOGRAPHY".

## Endpoints (desk app)

| method | path | result |
|---|---|---|
| GET | `/` | HTML desk page, links exactly one download |
| GET | `/downloads/field-kit.zip` | the materials (40019 B) |
| GET | `/health` | `{"status":"ok"}` |
| POST | `/submit` `{"answer":"..."}` | `{"ok":...,"message":"..."}` — receipt = flag |
| GET | `/submit` | 405 |

Everything else probed (`/downloads/`, `/downloads/session.log`, `/artifacts`,
`/timeline`, `/spool`, `/takes`, `/api`, `/status`, `/flag`, `/list`, `/files`,
`/receipt`, `/answer`, `/console`, `/admin`, `/index.html`, `/robots.txt`, and 30+
candidate download filenames such as `session.log`, `spool.log`, `timeline.txt`,
`original.zip`, `processed.zip`, `field-kit-2.zip`, `capture.pcap`, …) → **404**.
The page's own JS (`/submit` form + a "console" form) exposes no other route.

## Artefacts (kept OUT of git)

Downloaded to `work/` (gitignored). URL `http://54.72.82.22:8470/downloads/field-kit.zip`.

| file | size | sha256 |
|---|---|---|
| `field-kit.zip` | 40019 B | `b61361388715d87c605ccdc52d19c110538cf4a0d456124ebf281936344c1940` |
| `process.core` | 32768 B | `c4e24dbb09ab8e6ae45acd4c420d23c9c80bc4b47e17bf0fa1f2d5e0cdf30b17` |
| `uplink.pcap` | 9282 B | `369d73933319c6b4550f2583a75b4df0db6a803fe56c333e7946443d56c87f69` |
| `modules.map` | 37 B | `444a153a3c5eda8b44e95878ed93d81f4b98bf266bd609b8d7f11879bf816eff` |
| `field-note.txt` | 119 B | `5b07a6f648f1a63fed11f720d4a9556d117f6a8c43b952adcf1c079a69290980` |

Zip is clean: no comment, no extra fields, all four entries share one mtime
(2026-10-01 03:59:42), no hidden bytes in the central directory.

`modules.map`:
```
00001000-00009000 rw-p studio-worker
```
(range `0x1000..0x9000` = 32768 B = exactly `process.core`, a memory region of a
process named `studio-worker`).

`field-note.txt`:
```
The camera spool retained a warm buffer after the blue-hour test. Original and processed takes were exported together.
```

## Wire format

`uplink.pcap` is `LINKTYPE_USER0` (DLT 147) — raw payloads, no link layer
(pcap header: magic `d4c3b2a1`, ver 2.4, snaplen 65535, network 147). 158 packets,
ts = `1800000000 + i` (1 s apart, no gaps), `incl_len == orig_len` for all, no
trailing bytes. Two ASCII-tagged record types:

```
NOI : b"NOI" + 40 bytes                        x150  (all 150 first, then…)
QRY : b"QRY" + seq(2, big-endian) + 30 bytes   x8    (…all 8 last)
```

QRY payload name = `<15 base32 chars>.img.field.test`. Arrival seq order is
`3,1,7,6,2,5,4,0` (out of order, like the sibling *matchday-replay*). seq → id:

| seq | id |
|---|---|
| 0 | `PZRA3C5MF2WARTI` |
| 1 | `6CYYWT3ECKT45IY` |
| 2 | `B256MK23FAQL2VY` |
| 3 | `PVC46ZEQQHTN7UI` |
| 4 | `FJQLJ6KV2NM66HY` |
| 5 | `BZDPUAPZ44P4WHQ` |
| 6 | `4N6YDDXKVZSNSDI` |
| 7 | `UORLITSJBNLJVUI` |

Each 15-char id is exactly-valid RFC4648 base32 (alphabet A–Z2–7, 15 chars = 9
bytes with the final 2 data bits in the 15th symbol — no bits lost). Decoding in
seq order gives the 72 "take" bytes:

```
7e620d8bac2eac08cd f0b18b4f6412a7cea3 0ebbe62b5b2820bd57 7d45cf649081e6dfd1
2a60b4f955d359ef1f 0e46fa01f9e71fcb1e e37d818eeaae64d90d a3a2b44e490b569ad1
```

## What the decoys are (all disproved)

* **`process.core` = 32768 bytes of `os.urandom`-quality noise.** Uniform
  histogram (chi² = 252.1, df 255; per-value counts 101–159, expected 128), all
  bit planes ≈ 0.500, mean 127.49 / std 73.90 (= ideal uniform), zero
  autocorrelation at every lag 1–4199, no repeated 8/16-byte blocks, no
  printable strings (also after XOR/ADD with any constant and in UTF-16), no
  zlib/gzip/bz2/lzma/raw-deflate decompression, no file magic. Rendered as an
  image at widths 64/128/256/512 → pure static. **Pure decoy.**
* **The 150 `NOI` packets are pure random** (the inherited "stacked noise frames
  with a per-position bias" lead is **false**): no per-column/per-position bias,
  no bit-plane bias, no FFT tone, no autocorrelation. XOR-reduce / column-sum /
  column-median of all 150 → nothing. Using any NOI frame (any 9-byte window) as
  a per-take keystream → only chance hits.
* **Packet timing / order channels:** ts strictly +1 s, uniform `tus`, all NOI
  before all QRY. No interval or ordering encoding.

## The cipher hypothesis (and where I got stuck)

The sibling **`chal/forensics/matchday-replay`** (solved, same desk-app family,
port 8450) is the template:

* custom USER0 pcap, decoy tag `IDLE` + `LIVE` records, out-of-order seq;
* seed ("replay card: afterglow-17") leaked in the zip's `session.log`;
* keystream `K = sha256(seed)`, **wrapped modulo `len(seed)`**;
* fragment byte *i* of packet *seq* uses `K[(fraglen*seq + i) % len(seed)]`, and
  fragments sit at flag offset `fraglen*seq`;
* answer `safctf{<uuid>}` → POST `/submit` → receipt flag.

Applying that here verbatim: fragment len = 9, so
`P[pos] = C[pos] XOR sha256(seed)[pos % len(seed)]`, and the plaintext should
start `safctf{`. That fixes the required keystream **prefix**:

```
sha256(seed)[0:7] == C[0:7] XOR b"safctf{" == 0d 03 6b e8 d8 48 d7
```

(a 56-bit filter — a huge candidate list can be screened with one sha256 each).
**No seed in any candidate list I could generate reproduces it**, so either the
seed is an unguessable literal *not present in the materials*, or the scheme
differs from matchday's. Note the seed is supposed to leak in a zip file
(matchday shipped `session.log`), but Long Exposure's only text files
(`field-note.txt`, `modules.map`) contain no card id — this is the blocker.

### Everything tried against the 72 take bytes (all negative)

* **XOR keystreams**: the matchday wrapped rule and the plain `pos%L` rule, over
  ~75k themed candidates (`blue-hour`/`bluehour`/`afterglow`/`studio-worker`/
  `long-exposure`/every word of `field-note.txt`+`modules.map`+page text, each
  bare and with `-N`, `_N`, `N`, `-0N`, `-000N` for N=0..299), plus every
  substring (len 1–64) of all text artefacts (16,275 of them), plus the **full
  rockyou wordlist bare — 14,344,390 words, 0 hits** on the crib — plus
  sha256/sizes/port/points/epoch. Crib = `sha256(seed)[0:7] == 0d036be8d848d7`
  (checked in both seq order and arrival order).
* **Known-plaintext derivation** for a short keystream period p≤7 (derive K from
  `safctf{`): all garbage. Frame-offset variant too.
* **NOI/`process.core`/pcap as keystream** at *every* offset (contiguous, wrapped
  and strided): `C XOR core[o:o+72]`, `C XOR noi[o:…]`, single-byte XOR/ADD, etc.
* **Block ciphers**: AES-ECB/CBC/CTR/CFB/OFB (key = sha256 of many seeds /
  of the names / XOR-stacked sha256(nameᵢ)) on both `C` and `process.core`; no
  PNG/JPEG/`safctf` output. RC4/ChaCha20 also tried by earlier passes.
* **Base32-layer tricks**: alt alphabets (hex/Crockford/z-base-32/reversed),
  LSB-first bit order, reversed strings, every constant alphabet rotation
  (sub/xor 0–31) then re-decode, 5-bit index packing — never printable.
* **Stacking / "long exposure" reductions** of the 8 takes: XOR/AND/OR, mean,
  median, mode, sum-mod-256, bit-majority → all random.
* **Take-to-take relations**: no take is a rotation of another, multisets differ,
  no XOR pair is printable.
* **Differential / accumulator inversion** ("undo the long exposure"): diff-XOR,
  diff-sub, diff-add across the 72 bytes and within each take, cumulative XOR,
  and the reverse — all random. Tiled XOR of `process.core` with the pcap / NOI /
  the takes — nothing.
* **Original-vs-processed**: XOR each take with every 9-byte window of every NOI
  frame (the "processed = original XOR signal" reading) → only chance hits.

## Reproduce

```
python3 chal/forensics/long-exposure/solve.py            # themed + text seeds
python3 chal/forensics/long-exposure/solve.py /tmp/rockyou.txt
```

Stdlib only; fetches the kit, parses the custom pcap, decodes the 8 base32 takes,
applies the `safctf{` crib as a `sha256(seed)[0:7]` filter, and (on a hit)
reconstructs the answer and POSTs it to `/submit`.

## Where I got stuck (precise)

The 72 take bytes are the only non-random payload, and they must XOR (or
otherwise combine) with a keystream whose first 7 bytes equal
`0d036be8d848d7` (given a `safctf{` plaintext). That constrains `sha256(seed)`
but I could not find the seed: unlike matchday-replay, **no card id / seed is
present in any shipped file** (both text files and both binary blobs are clean),
and exhaustive brute over themed strings, all text substrings, the full rockyou
wordlist, and container/cipher variants all failed. The generator family's
seed-leak file appears to be missing (or the obfuscation is not matchday's
periodic-XOR). Next step that would crack it: the exact seed literal (or the
challenge generator), or a confirmed alternative transform on the 72 bytes.
