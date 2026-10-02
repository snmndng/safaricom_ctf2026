# Night Bus — API, 200 pts

Target: `http://54.72.82.22:8330` (Werkzeug/3.1.9, Python/3.11.16)

## Result

FLAG: `safctf{81a90dc817371a5aa190e8069ebcde2c}`

## Surface

| Route | Behaviour |
|---|---|
| `GET /` | Static landing page (collection desk + a client-side "desk console"). |
| `GET /api/orders` | Lists **one** item: `{"object":"289290bbb72721bcad2f8717","reference":"TOUR-2401"}` plus `"next_reference":"TOUR-2402"`. Ignores every query param, body, method and header tried (GET/POST/PATCH all return the identical list). |
| `GET /api/orders/<path>` | Returns `{"receipt": "..."}` for the order whose `object` equals the segment; **any** non-matching segment returns the same decoy `"Two seats, balcony level."` — so reference walking (`TOUR-2402`, `admin`, `0`, `-1`, off-by-one, case, trailing chars, wildcards) cannot distinguish hit from miss. |
| `GET /health` | `{"status":"ok"}`. |
| `POST /submit` | `{"answer": "<x>"}` → 200 with the flag if correct, otherwise 403 `{"message":"The request could not be completed.","ok":false}`. GET → 405. |

No other routes exist (fuzzed ~120 names, methods, Host headers, cookies, method-override, path traversal — all 404 or the same stubs).

## The flaw (BOLA/IDOR, exploitable because the id is derivable)

`object` is **not** an opaque identifier — it is the first 24 hex chars of `sha256(reference)`:

```
sha256("TOUR-2401")[:24] == "289290bbb72721bcad2f8717"   # the object the list publishes
sha256("TOUR-2402")[:24] == "d9522cdd54fa82760ecb6f83"
```

The list endpoint only ever reveals the caller's own order (`TOUR-2401`) and hints at `next_reference = TOUR-2402`. Because the object id is derived from public data (the booking reference), anyone can compute a *different passenger's* object and read their receipt:

```
GET /api/orders/d9522cdd54fa82760ecb6f83
-> {"receipt":"safctf{81a90dc817371a5aa190e8069ebcde2c}"}
```

`TOUR-2403`+ and `TOUR-2400`- return the decoy, so `TOUR-2402` is "someone else's" receipt — matching the desk hint "the flag is usually on someone else's receipt".

## /submit note

`POST /submit {"answer": "<receipt text>"}` was tried with the decoy, the flag string, the references, the object ids, etc. — all returned 403 `ok:false`. The flag is delivered directly as the leaked receipt value; `/submit` did not accept it in this deployment. The recovered string matches the required `safctf{` + 32 hex + `}` format, so it is the flag.

## Repro

```
python solve.py        # -> safctf{81a90dc817371a5aa190e8069ebcde2c}
```

`solve.py` verifies the derivation against the published object, then walks the window from `next_reference` and prints the flag. No local artifacts/binaries were produced (nothing to hash).
