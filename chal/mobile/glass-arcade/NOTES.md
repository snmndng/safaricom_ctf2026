# Glass Arcade — mobile, 300 pts

Target: http://54.72.82.22:8380 (desk app; `GET /submit` -> 405)

## Artifacts
- glass-arcade.apk — http://54.72.82.22:8380/downloads/glass-arcade.apk
  sha256 `febed208ade7c620bd7ec6a927ca5960e07071f7d2e7dc63d85b381bef0c3f57` (71 KB, not committed)
- session.json — `{"account":"cc8914d136ec62f6","build":3,"transfer":"P9noumCVAhimnBVdDcWUyA=="}`

## APK contents
`AndroidManifest.xml`, `classes.dex`, `assets/session.bin` (72 bytes). No `lib/`, no `res/`.
Only class: `com.glass.arcade.Lobby` (jadx).

## Scheme (Lobby.visit)
- 16-byte `transfer` blob from session.json is XORed with hardcoded constants
  (written as `(A - B) ^ blob[i]` puzzles in the smali, e.g. `(80-0)^t[0]`):
  `bArr[i] = (CONST[i] & 0xff) ^ transfer[i]`
- `MessageDigest.digest("glass-arcade/3".getBytes())` is called *after* `update(bArr)` —
  Java's `digest(input)` appends the input then finalizes, so
  `key = SHA-256(bArr || b"glass-arcade/3")` (16-byte AES-128 key).
- `assets/session.bin` = `12-byte GCM nonce || ciphertext || 16-byte GCM tag`.
- `AES/GCM/NoPadding` decrypt -> plaintext receipt.

`account` is a decoy — `visit()` only consumes the `transfer` string.

## Result
Intermediate plaintext: `safctf{3e6a8997-13d3-4615-9b47-0e41d40c9dee}` (NOT the answer).
`POST /submit {"answer": "<intermediate>"}` -> graded flag:

**`safctf{318223415bd0e96e2f63b0dd88eacf2d}`**

## Reproduce
```
/home/nomad/safaricom_ctf/.venv/bin/python solve.py
```
