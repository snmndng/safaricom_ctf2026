# Midnight Feedback

- **Category:** web
- **Points:** 450
- **Target:** `http://54.72.82.22:8111`
- **Status:** ✅ SOLVED

## Flag

```
safctf{f0e94a82-6662-4649-8b44-cb6fd2f8323a}
```

## Fingerprint

```
Server: gunicorn
app: Flask (Werkzeug-style 404 / 405 pages)
```

Public site is **"Birchwood Post"** — "Leave a note on the hill." The blurb:

> Leave a note on the hill. A keeper reads the board every few minutes — and the
> review console isn't as careful as it looks. Reach the reviewer, slip into the
> hollow, and take what the staff keep there.

## Route map

| Route | Method | Result |
|---|---|---|
| `/` | GET | Landing page: `POST /feedback` note form |
| `/feedback` | POST | Stores a note, `302 -> /thanks` |
| `/thanks` | GET | "Pinned to the board" confirmation |
| `/admin/login` | GET/POST | Keeper's desk login; bad creds -> `200` "Invalid credentials" |
| `/admin` | GET | `302 -> /admin/login` |
| `/admin/notes` | GET | `403 Unauthorized` — the "hollow" |

## The bug: client-controlled `role` cookie

The console guard reads the role straight from an unsigned cookie. There is no
server session involved — `/admin/notes` is authorized purely by:

```
Cookie: role=admin
```

`role=keeper`, `role=staff`, `role=administrator`, `role=ADMIN` all still 403;
only the exact string `admin` passes. Login is a decoy (no credential pair
worked); the guard never consulted it.

The response is a page titled **"The hollow"** containing:

```html
<div class="secret">safctf{f0e94a82-6662-4649-8b44-cb6fd2f8323a}</div>
```

## Solve

```bash
curl -s http://54.72.82.22:8111/admin/notes -H 'Cookie: role=admin'
# or: python3 solve.py
```

The intended path was probably stored XSS to the keeper bot, which would set
this same `role=admin` cookie in the admin's browser — but since the cookie is
attacker-forgeable, the bot is unnecessary.

## Notes / dead ends

- Route enumeration (`/board`, `/notes`, `/wall`, `/review`, `/keeper`, `/staff`,
  `/flag`, `/.env`, `/api/notes`, ...) all 404.
- Auth-bypass header spray (`X-Forwarded-For`, `X-Original-URL`,
  `X-Rewrite-URL`, Basic auth, `admin=1`, `is_admin=1`) all 403 — the cookie is
  the only bypass.
- `http.server`-style note: this host's gunicorn drops python-`requests`
  keep-alive connections (read timeout); use `http.client` with
  `Connection: close`.
