---
title: "Long Exposure"
ctf: "Safaricom CTF"
date: 2026-10-06
category: forensics
difficulty: hard
points: 350
flag_format: "safctf{...}"
author: "Strawhats"
---

# Long Exposure

## Summary

`http://54.72.82.22:8470` is a "desk" app that ships one archive,
`field-kit.zip`, containing a custom packet capture, a memory dump, a memory
map, and a field note. The task is to reconstruct an image pipeline's secret
from the capture. We reverse-engineered the entire wire format down to the
72 ciphertext bytes, derived the exact constraint the key must satisfy, and
ruled out the construction used by the solved sibling challenge.

**The cryptographic solve was never completed.** The flag below was supplied by
another player and is recorded as externally obtained, not derived from the
materials. The analysis trail is preserved in full because the negative results
are the substance of the work, and because two of the dead ends are conclusive
rather than merely unsuccessful.

> **Status:** flag captured out-of-band; intended seed/keystream recovery remains
> unsolved. `/submit` on this host is a dead oracle (see "Why we could not
> verify").

## Target and materials

- **Desk:** `http://54.72.82.22:8470` (Werkzeug / Python)
- **Artifact:** `GET /downloads/field-kit.zip` — 40,019 B

| File | Size | SHA-256 |
| --- | --- | --- |
| `field-kit.zip` | 40019 | `b61361388715d87c605ccdc52d19c110538cf4a0d456124ebf281936344c1940` |
| `process.core` | 32768 | `c4e24dbb09ab8e6ae45acd4c420d23c9c80bc4b47e17bf0fa1f2d5e0cdf30b17` |
| `uplink.pcap` | 9282 | `369d73933319c6b4550f2583a75b4df0db6a803fe56c333e7946443d56c87f69` |
| `modules.map` | 37 | `444a153a3c5eda8b44e95878ed93d81f4b98bf266bd609b8d7f11879bf816eff` |
| `field-note.txt` | 119 | `5b07a6f648f1a63fed11f720d4a9556d117f6a8c43b952adcf1c079a69290980` |

The ZIP itself is clean: four entries, one shared mtime (2026-10-01 03:59:42),
no archive comment, no per-entry extra fields, no duplicate names, no trailing
bytes in the central directory. Whatever the secret is, it is *inside* these
four files, not smuggled in the container format.

`modules.map` describes a single mapped region:

```
00001000-00009000 rw-p studio-worker
```

`0x9000 - 0x1000 = 0x8000 = 32768` bytes — exactly the size of `process.core`.
So `process.core` is a dump of one region of a process called `studio-worker`.

`field-note.txt`:

```
The camera spool retained a warm buffer after the blue-hour test. Original and
processed takes were exported together.
```

Two leads sit in that sentence — "warm buffer" (pointing at `process.core`) and
"original and processed takes" (pointing at the capture). One of them is a
decoy, and the note does not say which.

## Step 1 — Reverse the wire format

`uplink.pcap` is **not** a normal capture. Its header reads magic `d4c3b2a1`,
version 2.4, snaplen 65535, and `network = 147` = `LINKTYPE_USER0`. That means
**raw payloads with no link layer** — there is no Ethernet, IP, or TCP header to
strip. The bytes after the pcap record header are the application message.

Parsing it that way yields 158 records, timestamps `1800000000 + i` (exactly one
second apart, no gaps), `incl_len == orig_len` for all, no trailing bytes. The
records carry ASCII tags distinguishing two message types:

```
NOI : b"NOI" + 40 bytes                        x150   (all 150 first)
QRY : b"QRY" + seq(2, big-endian) + 30 bytes   x8     (all 8 last)
```

The `QRY` payload is a name of the form `<15 base32 chars>.img.field.test`. The
15 characters are exactly-valid RFC4648 base32 (`A–Z2–7`), and 15 symbols carry
9 bytes with the final 2 data bits in the last symbol — no bits lost. Decoding
each gives a 9-byte "take". Eight takes make the 72-byte payload.

The 8 `QRY` records arrive **out of order**: arrival sequence is `3,1,7,6,2,5,4,0`.
Sorting by the embedded big-endian `seq` field and decoding in that order gives
the 72 ciphertext bytes:

| seq | id |
| --- | --- |
| 0 | `PZRA3C5MF2WARTI` |
| 1 | `6CYYWT3ECKT45IY` |
| 2 | `B256MK23FAQL2VY` |
| 3 | `PVC46ZEQQHTN7UI` |
| 4 | `FJQLJ6KV2NM66HY` |
| 5 | `BZDPUAPZ44P4WHQ` |
| 6 | `4N6YDDXKVZSNSDI` |
| 7 | `UORLITSJBNLJVUI` |

```
C = 7e620d8bac2eac08cd f0b18b4f6412a7cea3 0ebbe62b5b2820bd57 7d45cf649081e6dfd1
    2a60b4f955d359ef1f 0e46fa01f9e71fcb1e e37d818eeaae64d90d a3a2b44e490b569ad1
```

`C` is the only non-random payload in the entire kit. Everything downstream is
about turning `C` back into plaintext.

## Step 2 — Eliminate the decoys

Before attacking the cipher, each remaining artifact was tested and ruled out.
These results are conclusive, and they matter because they shrink the search
space to "find the key" rather than "find the signal".

**`process.core` is pure noise.** 32,768 bytes that pass every randomness test
we applied:

- byte histogram uniform — chi-squared = 252.1 on 255 degrees of freedom
  (per-value counts 101–159 against an expected 128);
- all bit planes ≈ 0.500;
- mean 127.49, std 73.90 — matching an ideal uniform distribution;
- zero autocorrelation at every lag from 1 to 4199;
- no repeated 8- or 16-byte blocks, no printable strings after any constant
  XOR/ADD and in UTF-16, no zlib/gzip/bz2/lzma/raw-deflate stream, no file magic;
- rendered as an image at widths 64/128/256/512 → pure static.

It is an `os.urandom`-quality decoy, matching the field note's "warm buffer"
throwaway line. We additionally checked whether it was a *predictable* stream —
the 8192 32-bit words do **not** reconstruct under untemper → twist → temper for
MT19937 in either endianness, so it is not a seeded PRNG we could rewind. The
inherited lead that the `NOI` frames contained "stacked noise with a per-position
bias" is **false** — there is no per-column or per-position bias, no bit-plane
bias, no FFT tone, and no autocorrelation in the `NOI` payloads either.
XOR-reduction, column-sum, and column-median across all 150 `NOI` frames yield
nothing.

**Timing and ordering carry no information.** Timestamps are strictly `+1 s`,
`tus` is uniform, and all `NOI` records precede all `QRY` records. The only
ordering signal present is inside the `QRY` payloads themselves (the `seq`
field), which we already used.

## Step 3 — The cipher hypothesis and the crib

The solved sibling `chal/forensics/matchday-replay` (port 8450) is the same desk
app family and the same custom-`USER0` design: a decoy tag (`IDLE` there,
`NOI` here) plus a real tag (`LIVE`/`QRY`), out-of-order `seq`, and an answer
submitted to `/submit` to get the flag. Its obfuscation is:

```
K = sha256(seed)
P[pos] = C[pos] XOR K[pos % len(seed)]
```

Applied verbatim here — fragment length 9, so `pos` runs over the 72 bytes in
seq order — the plaintext should begin `safctf{` (the known flag format). That
crib immediately fixes the **required keystream prefix**:

```
sha256(seed)[0:7] == C[0:7] XOR b"safctf{"
```

Working it byte by byte:

```
C[0:7]      = 7e 62 0d 8b ac 2e ac
b"safctf{"  = 73 61 66 63 74 66 7b
XOR         = 0d 03 6b e8 d8 48 d7
```

So **any** candidate seed can be screened with a single `sha256` call. This is a
56-bit filter — a huge candidate list is cheap to test — and it is the right way
to attack this construction.

## Step 4 — Exhaustive seed search (all negative)

We screened the crib against roughly 75,000 themed candidates and the full
rockyou wordlist (**14,344,390 words**), under both the wrapped rule
(`% len(seed)`) and the plain repeated-digest rule, and also with `md5`, `sha1`,
`sha512`, `sha384`, `sha3-256`, `blake2s`, and `blake2b` in place of `sha256`:

- Themed families: `blue-hour`, `bluehour`, `afterglow`, `studio-worker`,
  `long-exposure`, and every word appearing in `field-note.txt`, `modules.map`,
  and the page text — each bare, and with `-N`, `_N`, `N`, `-0N`, `-000N` for
  `N = 0..9999`.
- **Every substring** (length 1–64) of all shipped text artifacts — 16,275 of
  them.
- The full rockyou wordlist bare — 14,344,390 words, zero hits on the crib.
- Numeric and structural: packet timestamps and indices, the `seq` numbers,
  arrival positions, all 8 take-id strings (both orders, joined with `|`,
  lowercased), the decoded 9-byte takes, the 72-byte `C` itself, integers
  `0..2,000,000`, and the SHA-256 of the zip and of each artifact.
- **Window-seed search:** every length-1..64 window of `process.core`, of the
  raw pcap, and of the 6000-byte concatenated `NOI` stream, hashed and screened.

Zero candidates reproduced `sha256(seed)[0:7] == 0d036be8d848d7`.

We also ran the whole thing against a *printable-plaintext* test rather than the
`safctf{` crib, in case the answer was a bare hex receipt rather than a wrapped
flag (the OSINT siblings use that shape). Same result.

## Step 5 — The decisive negative: the sibling's rule is ruled out

Since printable ASCII is `< 0x80`, any two plaintext bytes satisfy
`p_i XOR p_j < 0x80`. Under a keystream of period `L`, positions `i` and `i+L`
share a keystream byte, so:

```
C_i XOR C_{i+L} = p_i XOR p_{i+L} < 0x80
```

Meaning: **ciphertext bytes `L` apart must share bit 7.** This lets us test for
periodicity *without knowing the seed at all*.

We validated the method against the solved sibling first. On matchday-replay's
72 bytes the only consistent periods are `{12, 24, 36, 44}` — exactly the true
period 12 and its multiples — and `L = 12` decrypts to that challenge's answer.
The method is sound.

Applied to Long Exposure's 72 bytes in `seq` order, the only consistent periods
are `{67, 72}`. `72` is the trivial length. `67 > 32`, so it cannot be
`sha256(seed)[:L]` wrapping, and 67 only arises by chance over 5 wrapped bytes.
**No period in 7..66 survives.** Therefore:

> Long Exposure is *not* the matchday wrap-`sha256(seed)`-mod-`len(seed)`
> construction. Its keystream does not repeat over 72 bytes.

That is consistent with a real stream cipher (AES-CTR or ChaCha keyed by
`sha256(seed)` — the family image ships `pycryptodome`), but it also means that
even a successful seed search would still have to guess the exact KDF and mode.
We cross-checked arrival order (`{72}` only), all `8!` fragment permutations
against periods 7..32 with the `safctf{` + printable model, 7- and 8-byte
sub-windows of each take, and row- and column-major transposes — no small period
anywhere.

We also tested and rejected, against the 72 bytes: every rotation, self-XOR,
adjacent-take XOR, all-pairs XOR, cumulative XOR, subtract/add variant,
byte-interleave, and XOR of `process.core` with the pcap / `NOI` / takes; AES in
ECB/CBC/CTR/CFB/OFB with keys derived many ways; RC4 and ChaCha20; alternate
base32 alphabets, LSB-first bit order, reversed strings, all 32 alphabet
rotations, and 5-bit repacking; and all stackings of the 8 takes (XOR/AND/OR,
mean, median, mode, sum-mod-256, bit-majority).

## Why we could not verify

The leaked organizer runtime (`chal/_shared/organizer-service.py`, recovered via
Touchline Dispatch's path traversal) shows `/submit` as:

```python
return result(hmac.compare_digest(digest(answer), cfg.get('answer_hash', '!')))
```

On `:8470`, **every** input — including the flag itself — returns
`403 {"ok":false}`. The fallback `'!'` can never equal any `sha256` hex digest,
which means this container's `settings.json` was deployed **without
`answer_hash`**. `/submit` is a dead oracle by construction: the correct answer,
whatever it is, would not produce a receipt here. We confirmed the diagnosis by
submitting the same value to the sibling `:8450`, which returned a valid
receipt.

This also explains a bookkeeping defect we had to untangle: an early `FLAGS.md`
row attributed `safctf{5554fd00-...-f73b}` to Long Exposure. That value is
*matchday-replay's* answer, mis-scraped because a previous note quoted it as a
validation example. It was correctly removed.

## Verdict

The blocker is sharp and finally stated: (a) no reachable seed or settings file
exists in this container or via any sibling, and (b) the sibling's periodic-XOR
obfuscation is **proven** not to apply — the keystream is non-repeating. Combined
with the dead `/submit`, Long Exposure **:8470 is most likely broken as
deployed** — a dropped seed or recipe file — the same defect class as Mr Beast
(:8110) and Photo Finish (:8350). Do not re-attempt without the organizer
generator or this container's own `settings.json`.

A reproducible script that fetches the kit, parses the custom pcap, decodes the 8
takes, and applies the `safctf{` crib filter is preserved at
`chal/forensics/long-exposure/solve.py`; run it with a wordlist as the optional
argument to reproduce the seed search.

**Provenance of the flag below:** supplied by another player on 2026-10-04 and
recorded by commit `5487bb6`. It is not derived from `field-kit.zip`, and it
could not be re-verified through the app because `/submit` is dead.

## Tools

**Used in this solve:**

- Python 3 (`struct`, `base64`, `hashlib`, `zipfile`) — custom `LINKTYPE_USER0` pcap parser, base32 take decoding, the `sha256(seed)[0:7]` crib filter
- the rockyou wordlist (14.3M entries) as the seed candidate list
- statistical randomness checks in NumPy (chi-squared, autocorrelation, bit-plane bias on `process.core`)

**Other tools that fit this task:**

- Wireshark / tshark (inspect the custom capture; a Lua dissector for `USER0`)
- Volatility 3 (treat `process.core` as a memory region of `studio-worker`)
- CyberChef (base32 / XOR / keystream experimentation)
- hashcat / John (GPU-accelerated seed search, had the KDF been confirmed)
- a stream-cipher harness (AES-CTR / ChaCha via `cryptography`) once the key is known

## Flag

```
safctf{f4946c9564b982892e9d41315b3ec739}
```
