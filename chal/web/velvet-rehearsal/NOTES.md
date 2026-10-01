# Velvet Rehearsal — WEB, 500 pts

Target: http://54.72.82.22:8310  (Werkzeug 3.1.9 / Python 3.11.16, Flask)
Flag: `safctf{1745c9cc8a433522796feb9cfb8275de}`

## App surface (mapped)

- `GET /` — landing page. A "Desk console" (client-side `fetch`) hints the app
  expects arbitrary method/path/header requests; the details panel documents the
  three API routes.
- `GET|POST|PATCH /api/members` → `{"members":["visitor@studio.test","director@studio.test"]}`
- `GET|POST|PATCH /api/recovery?member=<email>` — "requests a sign-in link".
  - `member` absent or == `visitor@studio.test` → `{"mailbox":[{"subject":"Your sign-in link","token":"<36 hex>"}]}`
  - `member` present and != visitor (e.g. `director@studio.test`, `x@y.z`) → `{"queued":true}`
- `GET|POST|PATCH /api/entry` — JSON body `{"token": "..."}` → "opens the lounge".
- `POST /submit` — second stage, gated the same way.
- `/api/*` has a JSON 404 handler (`{"message":"Not found"}`); unknown top-level
  paths use the HTML 404.

## Gating behaviour of `/api/entry`

- token is a `str` but not accepted → `403 {"message":"The request could not be completed.","ok":false}`
- token is a list/dict (unhashable) → `400 {"message":"Request unavailable."}`

The 400-vs-403 split shows the check is a set/dict membership test
(`token in VALID`): unhashable values raise `TypeError` (caught → 400), hashable
wrong values simply miss (403). A JSON **string** body (not object) → `500`,
confirming `request.get_json(...).get(...)`.

Every token handed out by a normal `/api/recovery` call is rejected by
`/api/entry` (403), so the mailbox token alone is not the credential — the token
that gets *registered* differs from the one that gets *displayed*.

## The bug — HTTP Parameter Pollution (HPP)

`/api/recovery` reads the `member` parameter twice with different semantics:

- the authorization / mailbox-selection check uses the **first** value
  (`request.values.get("member", "visitor@studio.test")`),
- the token that is generated and stored is derived from the **last** value
  (e.g. `request.values.getlist("member")[-1]`).

So sending the parameter twice returns the *visitor* mailbox (readable) while
registering a token belonging to the *privileged* member:

```
POST /api/recovery?member=visitor@studio.test&member=director@studio.test
  -> {"mailbox":[{"subject":"Your sign-in link","token":"<T>"}]}
POST /api/entry   {"token":"<T>"}
  -> {"message":"safctf{1745c9cc8a433522796feb9cfb8275de}","ok":true}
```

Order matters: `member=director&member=visitor` hits the queue branch
(`{"queued":true}`), while `member=visitor&member=visitor` yields a token that is
correctly rejected (visitor, not privileged).

### What did NOT work (dead ends checked)

- Single `member` value, any case/encoding/type juggling (`director@studio.test`,
  arrays, dicts, JSON body, `%00`, unicode) → only ever `queued` or a
  non-privileged mailbox token.
- Token forecasting / derivation: tokens are uniform 36-hex (`secrets.token_hex(18)`-like),
  never repeat, and don't match md5/sha of the emails or plausible salts.
- Placement fuzzing: token as query/form/cookie/`X-*`/`Authorization` header on
  both `/api/entry` and `/submit` → 403.
- Race conditions (many concurrent queue+read pairs) → nothing.
- Hidden routes, backups, `.env`, `/static/*`, path traversal → none.

## Reproduce

```
python3 solve.py [http://54.72.82.22:8310]
# -> safctf{1745c9cc8a433522796feb9cfb8275de}
```
