# Crown Studio — WEB / ACTIVE DIRECTORY, 550 pts

- **Target:** http://54.72.82.22:8590  (Werkzeug 3.1.9 / Python 3.11.16, Flask)
- **Status:** ✅ SOLVED
- **Flag:** `safctf{04fd9ff98e41c5ef8a54da3990126b58}`

## App surface (fully mapped)

Only five routes exist (verified by fuzzing ~150 path words × GET/POST/PATCH):

| Route | Behaviour |
| --- | --- |
| `GET /` | landing page; a client-side "Desk console" that can send arbitrary method/path/headers/body |
| `GET /health` | `{"status":"ok"}` |
| `GET /downloads/studio-directory.zip` | 850-byte zip: `templates.json`, `directory.json`, `client.json` |
| `POST /api/enroll` | body `{template, upn}` → `{"certificate":"<JWT>"}` |
| `POST /api/session` | body `{certificate}` → `{"message":"<flag>","ok":true}` |
| `POST /submit` | GET → 405; rejects every value tried (see below) |

No `/static`, no source leak, no path traversal on `/downloads/`
(`/downloads/../app.py`, `%2e%2e`, `%252f`, … all 404).

## Artifacts

`directory.json` → `{"members":["visitor@orchard.test"],"archiveCustodian":"archivist@orchard.test"}`
`client.json` → `{"enroll":"POST /api/enroll: template, upn","session":"POST /api/session: certificate"}`

`templates.json` — 25 "designs", each with four AD CS-style flags:

```json
"design-80015a51f6": {"enroll":"members","clientAuth":true,"approval":false,"supplySubject":true}
```

`enroll` (group), `clientAuth` (Client-Auth EKU), `approval` (CA approval),
`supplySubject` (enrollee supplies the subject — i.e. the **ESC1** enabler).

## 400 vs 403 (useful oracle)

- Well-formed request that isn't permitted → `403 {"message":"The request could not be completed.","ok":false}`
- Structurally wrong body → `400 {"message":"Request unavailable."}`

This mirrors sibling challenge **velvet-rehearsal** (8310): the split is an
unhashable-key `TypeError` caught into 400 vs. a set/dict membership miss 403.
For `/api/session`, `{"certificate": <dict|list|int|null>}` → 500/400, while a
3-segment base64url-JSON string → 403 — i.e. the endpoint does a membership test
against CA-issued certificates and never verifies the signature cryptographically.

## Exploit — AD CS ESC1

The signed-in client is a plain **member** (`visitor@orchard.test`). One design
is the textbook ESC1 hole:

```
design-80015a51f6 → enroll: members, clientAuth: true, approval: false, supplySubject: true
```

`supplySubject` lets an ordinary member request a certificate for *any* UPN, and
`clientAuth` gives it the Client Authentication EKU, so it is accepted by the
session endpoint. `approval: false` means no CA manager sign-off is required.

```
POST /api/enroll   {"template":"design-80015a51f6","upn":"archivist@orchard.test"}
  -> 200 {"certificate":"eyJhbGciOiAiSFMyNTYiLCAidHlwIjogIkpXVCJ9.eyJ1cG4iOiAiYXJjaGl2aXN0QG9yY2hhcmQudGVzdCJ9.UL7WTDBwvDTRoOOJSTmI4FnlTfrBKGQblDj7CyhLtKQ"}
POST /api/session  {"certificate":"<that>"}
  -> 200 {"message":"safctf{04fd9ff98e41c5ef8a54da3990126b58}","ok":true}
```

The certificate is an HS256 JWT whose payload is just `{"upn":"archivist@orchard.test"}`.
The signature is deterministic (`UL7WTDBw…`), so the value is stable across runs.
No key recovery was needed: the certificate is simply *redeemed* against the
CA's issued set; forging one (any HMAC/`alg:none`/`sha256` variant, ~25k payload
permutations) always missed.

## Dead ends checked

- `/api/enroll` is **not** reachable by static guessing: the gate is
  template-specific. Every template 403s *except* `design-80015a51f6`. It is a
  full 25-template × 8-upn sweep that surfaces it — a partial sweep misses it.
- Path traversal / source leak on `/downloads`, `/static`, `/.env`, `/.git`.
- JWT forgery: `alg:none`, HS256/384/512 with empty/derived/artifact-wordlist
  keys (334 candidates), `sha256`/`md5`/raw-`b64` "signatures", header/payload
  claim fuzzing (~25,000 header×payload permutations) — all 403.
- `/api/enroll` auth-header / Basic-auth / query-param / HPP fuzzing — all 403.
- `/submit` (the shared desk second-stage) rejects the flag, the certificate,
  the UPN, the template id, the bare hex, and all common answer keys.

## Reproduce

```
.venv/bin/python chal/web/crown-studio/solve.py
```
