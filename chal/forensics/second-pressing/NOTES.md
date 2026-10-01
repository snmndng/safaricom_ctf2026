# Second Pressing — FORENSICS (500 pts)

**Target:** http://54.72.82.22:8460 (Werkzeug/Flask)
**Flag:** `safctf{34a793a0d11032abb97236fafc9b30c4}`

## Artifact

- Download page: `/` → links `/downloads/listening-room.zip`
- `http://54.72.82.22:8460/downloads/listening-room.zip`
- size 1034 bytes
- sha256 `d3e482840703c654072a102216e23d694c0230b09c79c5da6b58ccc8e2a95f82`
  (kept out of git per repo `.gitignore`)

Zip members (mode `-rw------- `, mtimes 2026-10-01 03:59):

| file | what |
|---|---|
| `library.db` | SQLite 3 DB, page size 4096, 2 pages, schema `CREATE TABLE pressings(id INTEGER PRIMARY KEY,title TEXT,receipt TEXT)` |
| `library.db-wal` | SQLite Write-Ahead Log, 8272 bytes, 2 frames, both page 2 |
| `library.db-shm` | WAL shared-memory index (red herring here) |
| `desk.log` | `16:41 test pressing queued` / `16:42 catalogue revised` / `16:43 counter closed` |

## Story / hypothesis

"Second Pressing" = a re-cut of a record. The catalogue row was **re-cut**
(overwritten) after the first pressing: `desk.log` says the catalogue was
"revised" at 16:42. Because SQLite was in **WAL mode**, the pre-revision page
was flushed to the WAL as a committed frame; the revision then wrote a newer
frame of the same page, truncating the `receipt` column down to the literal
string `withdrawn`. The original, intact `receipt` (a base64/zlib blob) is
therefore still sitting in the *older* WAL frame.

The landing page script also exposes a `/submit` endpoint taking
`{"answer": ...}` and hints: "Keep your collection receipt when your visit is
complete." So the recovered receipt is the answer key.

## Technique — SQLite WAL forensics

WAL layout: 32-byte header (`magic=0x377f0682`, page size 4096) followed by
frames of `24 + 4096` bytes; each frame header is `pgno (u32), commit (u32),
salt1, salt2, cksum1, cksum2`.

Both frames target page 2. Decoding page 2 of each frame:

- frame 0 (older): `Test pressing` + `eJwrTkxLLkmrNjRKSko2NUzRNTcxNdA1MUk2001MM07TNTQ3MjY1NEmySExMqQUALKEM0A==`
- frame 1 (newer): `Test pressing` + the same base64 truncated to 48 chars, then `Test pressingwithdrawn`

The base64 column value is glued to its label with no separator, so a naive
base64 decode fails; sliding the start offset and letting zlib's integrity
check reject the wrong alignments recovers it:

```
base64 → zlib.decompress → b'safctf{12bbc51d-7450-44c6-af3f-1723514b8aad}'
```

That UUID is the **collection receipt**. It is NOT the final flag — it is the
`answer` the app wants. POST it to `/submit`:

```
$ curl -s -X POST http://54.72.82.22:8460/submit \
      -H 'Content-Type: application/json' \
      -d '{"answer":"safctf{12bbc51d-7450-44c6-af3f-1723514b8aad}"}'
{"message":"safctf{34a793a0d11032abb97236fafc9b30c4}","ok":true}
```

A wrong answer (`{"answer":"nope"}`) returns `{"message":"The request could not
be completed.","ok":false}`, confirming the receipt is the required key.

## FLAG

```
safctf{34a793a0d11032abb97236fafc9b30c4}
```

(`safctf{12bbc51d-7450-44c6-af3f-1723514b8aad}` is the intermediate receipt
recovered from the WAL, not the graded flag.)

## Repro

`python3 solve.py` — fetches the zip, parses the WAL, recovers the receipt,
submits it, prints the flag. Verified reproducible.
