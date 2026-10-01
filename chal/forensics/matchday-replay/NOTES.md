# Matchday Replay

- **Category:** forensics
- **Points:** 300
- **Branch:** `chal/forensics-matchday-replay`
- **Target:** `http://54.72.82.22:8450`
- **Status:** ✅ SOLVED

## Flag

```
safctf{e2d6cc7b320577dd3eb54aa08f86e446}
```

This is the **receipt** returned by the challenge's own `/submit` once the
pcap-derived answer is correct. The page says *"Keep your collection receipt when
your visit is complete"* — so the receipt, not the answer, is the flag.

The answer unlocked from the capture is:

```
safctf{5554fd00-017a-4915-a883-a7ef2639f73b}
```

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
