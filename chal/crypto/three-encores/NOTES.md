# Three Encores — CRYPTO (300 pts)

Target: http://54.72.82.22:8420 (Flask/Werkzeug 3.1.9)

## Recon

`GET /` is a themed landing page titled **Three Encores**, tagline
"A familiar melody in three different rooms." One download link:
`/downloads/programme.json`. `/download`, `/file`, `/static/`, `/robots.txt`
are all 404. `/submit` accepts `POST` with JSON `{"answer": ...}`.

## The material

`programme.json` contains `deliveries`: **three** RSA records, each with
`n`, `e`, `c`. Every record has `e = 3`, and — critically — **all three `c`
values are byte-identical**.

## Solving

Classic setup for the **Håstad broadcast attack** (e=3, three moduli, same
plaintext). But it collapses immediately:

- `c` is 1293 bits, each `n` is ~1535–1536 bits.
- Since `c` is identical across all three moduli and `m^3 = c` fits in
  ~1293 bits (**under** every `n`), there is no modular reduction at all:
  the ciphertext *is* `m^3`.
- A plain integer cube root recovers `m` exactly (the CRT over the three
  moduli gives the same number, `k=0` branch).

```
m = 0x70726f6772616d6d653a7361666374667b...  (431-bit integer)
  = b"programme:safctf{dadb56ae-eede-422e-87cb-744462cdfda0}"
```

### Three "encores"

The title is a decoy: the three deliveries are not three distinct layers —
they are the same layer repeated three times, and the naive e-th root works
without any CRT.

## Getting the scored flag

The decrypted blob carries an *intermediate* value. `POST /submit` with
`{"answer": "safctf{dadb56ae-eede-422e-87cb-744462cdfda0}"}` (the inner
`programme:safctf{...}` prefix must be stripped — the bare `safctf{...}`
inner flag is the accepted answer) returns:

```json
{"message": "safctf{0471ad15e84bb9f630e394e49dde85a9}", "ok": true}
```

A wrong answer returns `{"message": "The request could not be completed.", "ok": false}`.
The returned flag is stable across repeat submissions and matches the expected
`safctf{` + 32 hex + `}` format.

## Flag

```
safctf{0471ad15e84bb9f630e394e49dde85a9}
```

(Decrypted intermediate: `programme:safctf{dadb56ae-eede-422e-87cb-744462cdfda0}`)

## Reproduce

```
python3 chal/crypto/three-encores/solve.py
```

Stdlib only (urllib) — no pycryptodome/gmpy2/sympy required.
