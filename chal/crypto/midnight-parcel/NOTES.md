# Midnight Parcel — CRYPTO 750

Target: `http://54.72.82.22:8440` (Werkzeug/Flask)

## Materials

- Page `/` advertises `GET /downloads/parcel.json`, `GET /api/parcel`,
  `POST /api/receipt` ("records its delivery status").
- `GET /api/parcel` and `/downloads/parcel.json` both return a single hex
  "parcel" of 192 hex chars = 96 bytes = 6 AES blocks.
  - sha256(parcel.json) = dc597b0ac08067114e38e99bfa89943e176b38585dacc558f1948f54a49dbb5e

## The flaw — CBC padding oracle

`POST /api/receipt {"parcel": <hex>}`:
- valid PKCS#7 padding  -> HTTP 202 `{"status":"pending"}`
- invalid padding       -> HTTP 422 `{"status":"damaged"}`

Only the *final* block's padding is inspected (flipping any byte of the last
ciphertext block, or the last byte of the preceding block, turns "pending" into
"damaged"; flipping earlier bytes is ignored). Classic CBC padding oracle.

Decryption strategy:
- Recover the last block's plaintext by mutating the block in front of it
  (standard byte-at-a-time padding reconstruction + a disambiguation test for
  the 0x01-vs-0x02 coincidence at the last byte).
- Then truncate the ciphertext so each earlier block becomes the final block and
  repeat.
- CBC lets us also *forge* arbitrary plaintext for any block by setting
  `C[i-1] = D(C[i]) XOR target`.

## Result — SOLVED

Decrypted parcel (5 plaintext blocks; the first ciphertext block is the IV):

```
Receipt for the evening delivery: safctf{8a99e6bb-7903-4f4e-b42a-7e594982528b}\x02\x02
```

That decoded string is **not** the flag the platform accepts — it is the
intermediate *answer*. The app has a POST-only `/submit` (`GET` → 405):

```
POST /submit  {"answer": "safctf{8a99e6bb-7903-4f4e-b42a-7e594982528b}"}
-> 200 {"message":"safctf{f895fa37be9a374582ff7694a4748862}","ok":true}
```

**GRADED FLAG = `safctf{f895fa37be9a374582ff7694a4748862}`**

The oracle decrypts to a *receipt*; the flag lives behind `/submit`. Note the
`answer` key is exact — `receipt`/`flag`/`value`/etc. all return the generic
403 wrong-answer body.

Note the leaked PKCS#7 pad `\x02\x02` — the 0x02 coincidence at the last byte is
what forces the disambiguation step in `solve.py`.

## Reproduce

`python3 solve.py` — pulls `/api/parcel`, runs the oracle (~2 min with 32
threads), prints the flag. No Sage needed.

## Blocking / notes

None. Runtime was limited only by the ~80 req/s the Werkzeug dev server gives
with a 32-thread pool.
