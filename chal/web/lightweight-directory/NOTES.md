# Lightweight Directory — WEB, 400 pts

Target: http://54.72.82.22:8070 (Werkzeug/3.1.9, Python 3.11.16)
Flag: `safctf{ef30111b835006ade7f00a9a4526d453}`

## Recon

- `GET /` -> 302 to `/connect`. Only two routes exist: `/connect` (login form),
  `/logout`. Everything else (`/admin`, `/directory`, `/flag`, `/robots.txt`,
  `/static/js/app.js`, ...) is 404.
- `POST /connect` with bad creds returns `Log in to Directory Failed`.
- Password field has a length guard: `>= 4` chars, otherwise
  `Password length not acceptable` (checked before any lookup).
- The session cookie is a Flask session: base64 `{"username":"admin"}` once
  authenticated. Not needed to forge — the injection logs you in directly.

## Hypothesis / Exploit

Name "Lightweight Directory" => LDAP. The app builds an LDAP filter from the
username/password, classically:

    (&(uid=<username>)(userPassword=<password>))

Classic LDAP auth-bypass injection in BOTH fields (password must be >= 4 chars,
and this payload is 16 chars):

    *)(uid=*))(|(uid=*)

Resulting filter collapses to a tautology matching the first directory entry
(admin), so a 302 to `/` is returned and we get an authenticated session as
`admin`. Username value is irrelevant (admin / `*` / junk all redirect).

Notably `*aaaaaaaaa` (star + padding) does NOT bypass — only the balanced
paren payload that closes `(uid=...` early works. This matches the
`(|(...)(...))` two-clause shape.

## Post-auth

Authenticated dashboard (`/`) as admin shows two links:

- `/config-update` — "Update Your Access ID" (form `new_username`) — unused for
  the flag.
- `/audit-export` — "Open team report" — response body IS the flag:

      safctf{ef30111b835006ade7f00a9a4526d453}

## Repro

    /home/nomad/safaricom_ctf/.venv/bin/python chal/web/lightweight-directory/solve.py http://54.72.82.22:8070

`solve.py` posts the injection payload to `/connect`, then GETs `/audit-export`
and prints the flag. Verified end-to-end: prints
`safctf{ef30111b835006ade7f00a9a4526d453}`.

## Notes / dead ends

- SQLi/NoSQL payloads (`' or 1=1--`, `admin'--`) do nothing; error text is
  LDAP-flavoured ("Directory Failed").
- Plain wildcards (`admin`, `*` in password) fail because they don't satisfy
  both clauses of the AND filter; the paren-balanced payload is required.
