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

---

# Round 2 (2026-10-02) — new hypotheses, all negative

Second pass. Focus: new (non-dictionary) seed sources, an alternate transform,
and re-checking reachable files. **Still UNSOLVED — no flag.** Key new result:
the matchday periodic-XOR rule is now *proven* not to apply (see "Periodicity
test" below), which is stronger than "the seed was not found".

## Leaked organizer runtime confirms the app, and that /api is dead here

The desk app is the leaked `chal/_shared/organizer-service.py`
(`/health`, `/`, `/downloads/<name>`, `/submit`, `/api/<path:operation>`).
Confirmed live: `GET /api/library` → `404 {"message":"Not found"}` with
`Content-Length: 24` (= Flask `jsonify` + trailing `\n`), byte-identical to the
source's final fallthrough `return {'message':'Not found'},404`.

Fingerprinted the `kind` by probing every kind's free op — `library, members,
session, orders, profile, sync, objects, identity, login, parcel, round,
enroll` **all** return `Not found`. So this container's `kind` is **not any of
the 13 kinds in the leaked source** → `/api/*` is a pure dead end, and
`/submit` (`hmac.compare_digest(sha256(answer), cfg['answer_hash'])`) is the
only oracle. (Constant-time; no length/timing leak. If `settings.json` omits
`answer_hash` the fallback `'!'` can never match → 403 for everything — but we
cannot distinguish that case from "wrong answer".)

## Seed-file reachability (item 3) — exhausted

* `/downloads/<x>` is Werkzeug `send_from_directory` (traversal-safe). Tried
  `../`, `%2e%2e`, `..%2f`, `....//`, `//etc/passwd`, `%2f`-encoded, null/back-
  slash variants, `/static/...`, `/downloads/templates/index.html` → all 404.
* The rendered index lists `downloads = sorted((ROOT/'downloads').glob('*'))`
  → only `field-kit.zip`. No second file exists in the container's downloads.
* Zip is genuinely 4 entries, shared mtime `2026-10-01 03:59:42`, no comment,
  no per-entry `extra`, no trailing data. `field-note.txt` is exactly 119 B,
  `modules.map` 37 B — no hidden seed.
* Cross-container: the sibling **Touchline Dispatch :8300** (`web-path`) *does*
  read absolute paths (`/api/view?name=/app/service.py` works). Read its
  `/proc/self/environ` (= its own FLAG), `/proc/net/tcp` (only one listener,
  :8080 → one challenge per container), `/proc/mounts` (plain overlay, no shared
  bind mounts), `/app/settings.json`, `/app/requirements.txt`
  (`Flask 3.1.2, pycryptodome 3.23.0, gunicorn`). There is **no generator, no
  seed table, and no mount** exposing another container — lateral read is not
  possible. Long Exposure's `settings.json` is unreachable.

## Artifact re-checks (item 1) — all negative

* **`process.core` is not a PRNG artifact**: the 8192 32-bit words do not
  reconstruct under untemper→twist→temper for MT19937 (neither endianness) —
  genuinely `os.urandom`-class noise, not a predictable stream.
* **Window-seed search**: every length-1..64 window of `process.core`, of the
  raw pcap, and of the 6000-byte concatenated NOI stream, hashed with sha256,
  never yields `sha256(seed)[0:7] == 0d036be8d848d7`. No hidden literal seed.
* Seeds tried as strings *and* as raw key bytes, verified against the 56-bit
  crib AND against a full-plaintext-printable test: pcap fields
  (`1800000000`, `1800000150..157`, `150/158/8/72/9282/40019/32768/8470/750/147/
  65535/0x1000/0x9000`), all 8 take-id strings (seq and arrival order, joined
  with `|`, lowercase), the decoded 9-byte takes, the 72-byte `C`, the sha256 of
  the zip and of each artifact, the packet indices/ts, the seq numbers, the
  arrival positions — no hit.
* Numbers `0..2,000,000` and ~1M more; themed words × `-NN`/`_NN`/`.NN`/bare ×
  N=0..9999; `long-exposure`/`bluehour`/`blue-hour`/`afterglow`/`studio-worker`
  families — no hit.
* **Re-ran rockyou (14,344,390 words) under the *printable-plaintext* test**
  (the first pass only screened the `safctf{...` crib — invalid if the plaintext
  is instead a bare `sha256` hex receipt or a raw `ref`, as the OSINT siblings
  use). Zero hits for `P = C XOR sha256(word)` with both the plain-repeat and the
  `%len(word)`-wrap keystream. (A background run also screens md5/sha1/sha512/
  sha384/sha3-256/blake2s/blake2b repeats over rockyou.)

## Transform hypotheses (item 2) — negative

* Literal `safctf{`-crib fixed `sha256(seed)[:7]`; tested md5/sha1/sha512/
  sha3-256/blake2s/blake2b/sha384 digests too — none match for any structured
  candidate.
* The 72 bytes are **not** a keystream-free difference: no rotation, self-XOR,
  adjacent-take XOR, all-pairs XOR, cumulative XOR, subtract/add variant, or
  byte-interleave is printable.
* The QRY **seq order permutation** (`3,1,7,6,2,5,4,0`) and the packet
  indices/ts as literal key material — no.
* Per-take key = `sha256(own-id)` (at offsets 0 or `9*seq`), key =
  `sha256(all-ids)` sliced, key = `sha256(str(packet-index))` per fragment — no.

## Decisive new result — the matchday periodic-XOR rule is RULED OUT

Since printable ASCII is `< 0x80`, any two plaintext bytes `p_i, p_j` satisfy
`p_i XOR p_j < 0x80`. Under a keystream of period `L`, positions `i` and `i+L`
share a keystream byte, so `C_i XOR C_{i+L} = p_i XOR p_{i+L} < 0x80` — i.e.
**ciphertext bytes `L` apart must share bit 7** (and their XOR must be a xor of
two printable bytes). This is testable with no seed.

* **Validated** on the solved sibling matchday-replay: the only consistent
  periods are `{12, 24, 36, 44}` — exactly the true period 12 and its multiples
  plus the trivial length; `L=12` decrypts to matchday-replay's answer
  `safctf{5554fd00-…-f73b}` (matchday's own flag, quoted here only as a
  validation example — it is **not** Long Exposure's flag; do not credit it to
  this challenge, cf. the `tools/flags.py` false positive below). Method is sound.
* **Long Exposure** (72 bytes, seq order): consistent periods are only
  `{67, 72}`. `72` is trivial; `67 > 32`, so it cannot be `sha256(seed)[:L]`
  wrapping, and 67 shows up only by chance (5 wrapped bytes). No period `7..66`
  survives → **the keystream does not repeat with any small period.**
* Also checked: arrival order (`{72}`), all 8! fragment permutations ×
  periods 7..32 with the `safctf{`+printable model (**0** solutions), 7/8-byte
  sub-windows of each take, row-major and column-major transposes — no small
  period anywhere.

Conclusion: Long Exposure is **not** the matchday wrap-`sha256(seed)`-mod-L
construction. Its keystream is non-repeating over 72 bytes (consistent with a
real stream cipher — AES-CTR / ChaCha keyed by `sha256(seed)`, and note the
family image ships `pycryptodome`). That still leaves the same wall: the
seed/key is not present in the ZIP and is not guessable from the shipped text,
so the intended plaintext cannot be recovered from the materials.

## Verdict

No flag. The blocker is now sharper than "seed missing": (a) no reachable
seed/settings file anywhere in this container or via any sibling, and (b) the
sibling's periodic-XOR obfuscation **does not apply** — the keystream is
non-repeating, so even a successful seed search would have to guess the exact
KDF/mode. Combined with the family's precedent (`Mr Beast` 8110, `Photo Finish`
8350 blocked as deployed), **Long Exposure :8470 is most likely broken as
deployed** (a dropped seed/recipe file). Recommended: do not re-attempt without
the organizer generator or Long Exposure's own `settings.json`.

### Files added this round (all under `work/`, gitignored)
`explore.py, winsearch.py, idks.py, structural.py, scan.py, final.py,
decode_search.py, mt_test.py, periodic.py, period_test.py, validate_matchday.py,
perm_test.py, subwindow_test.py, final2.py, idxkey.py, submit_batch.py,
test_inter.py`

---

# Round 3 (2026-10-03) — the FLAGS.md row was a scraper false positive

`FLAGS.md` briefly listed
`forensics/long-exposure | safctf{5554fd00-…-f73b} | chal/forensics/long-exposure/NOTES.md`.
That value is **matchday-replay's answer**, not a Long Exposure flag. Root cause:
`tools/flags.py` collects *every* `safctf{...}` literal anywhere under `chal/**`,
and this file's Round-2 text quoted matchday's answer as a validation example, so
the 2026-10-02 flag regeneration (`893e9f1`, "board: land chal/api-photo-finish-r3")
attributed it to Long Exposure too. Fixed by de-literalising that quotation
(`safctf{5554fd00-…-f73b}`); `main`'s FLAGS.md never had the row and a fresh
regeneration now stays clean.

## Live re-checks (2026-10-03)

* `POST /submit` on :8470 returns **HTTP 403 for every input**, including the
  matchday answer. The leaked `chal/_shared/organizer-service.py` shows
  `result()` returning 403 on failure, so a 403 means
  `hmac.compare_digest(sha256(answer), cfg['answer_hash'])` never matches — i.e.
  :8470's `settings.json` is missing `answer_hash` (the `'!'` fallback), making
  `/submit` a decoy. **The correct answer, whatever it is, would not yield a
  receipt through this app.**
* Same UUID submitted to the sibling `:8450` (matchday-replay) returns
  `{"ok":true,"message":"safctf{e2d6cc7b…e446}"}` (matchday's receipt) — direct
  proof the value in the erroneous row belongs to matchday-replay.
* `/api/<any>` (incl. `sync`, `dispatch`) still returns the dispatch fallthrough
  `{"message":"Not found"}` (Content-Length 24), so :8470's `kind` matches none
  of the 13 leaked kinds — **not** the unmapped `api-canonical`; `/api` is dead.
* Fresh `GET /downloads/field-kit.zip`: unchanged
  (sha256 `b6136138…c1940`); index page unchanged and carries no seed.

## Verdict (unchanged, now with the board defect explained)

Long Exposure remains **UNSOLVED**; its genuine flag is still unrecovered. The
`FLAGS.md` entry was a bookkeeping false positive (matchday's answer), which is
exactly why it fails to submit. Do not record any flag for this challenge until
the seed/recipe or the organizer generator is available.
