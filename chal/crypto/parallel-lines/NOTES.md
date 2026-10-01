# Parallel Lines — CRYPTO (500 pts) — SOLVED

Target: http://54.72.82.22:8430 (Werkzeug/Flask)
Flag: `safctf{8d6447b3f694f59efef1f015f58d04a7}`

## Material

`GET /downloads/lookbook.zip` yields four files:

| file            | size | contents |
|-----------------|------|----------|
| `memo.txt`      | 153  | 71 chars of prose: `Studio memo: sample garments arrive Tuesday. Keep the silver rack clear. ` followed by 82 `.` filler bytes |
| `export-a.bin`  | 153  | random-looking ciphertext |
| `export-b.bin`  | 64   | random-looking ciphertext |
| `spool.json`    | —    | `{"nonce":"ba2cbe7787a82ddb", "spool_order":[...153 ints...]}` |

`spool_order` is a permutation of `0..152` — the size of `export-a.bin`.
The `nonce` is 8 bytes (CTR-family width) but is not needed for the break.

`/submit` (POST JSON `{"answer": ...}`) is the checker; `/health` returns
`{"status":"ok"}`. Generic 404/405 elsewhere.

## Hypothesis tested and confirmed

The two exports are "parallel": **the same keystream is reused** (CTR nonce
reuse), and `export-a` was emitted out of spool order so it must be re-sorted
before it can be XORed against the known `memo.txt` plaintext.

1. Undo the permutation: `fixed[spool_order[i]] = export_a[i]`.
2. Recover the keystream: `ks = fixed XOR memo` (all 153 bytes of `memo`
   are known, including the `.` filler).
3. Decrypt the second export with the same keystream:
   `export_b XOR ks[:64]`.

Result:

```
Collection receipt: safctf{0983d7d0-b930-468f-ac25-ecc6feecc856}
```

The `safctf{...}` inside the receipt is **not** the challenge flag — it is a
receipt token. The checker only accepts that token:

```
POST /submit {"answer":"safctf{0983d7d0-b930-468f-ac25-ecc6feecc856}"}
-> {"message":"safctf{8d6447b3f694f59efef1f015f58d04a7}","ok":true}
```

Submitting the returned flag directly is rejected (`ok:false`), confirming the
receipt token is the input and the returned 32-hex value is the real flag.

## Attempts / dead ends (kept for the record)

- Raw (non-permuted) `export-a` XOR `memo` gave no structure.
- Applying the permutation in the other direction (`out[i] = a[order[i]]`) gave
  garbage; only the inverse mapping works.
- `export-a XOR export-b` (truncated) gave no structure — the reuse only
  becomes visible once `export-a` is re-sorted.

## Reproduction

```
python3 solve.py            # stdlib only, no deps
```

Dependencies: none beyond the Python standard library
(`urllib.request`, `json`, `zipfile`, `io`).
