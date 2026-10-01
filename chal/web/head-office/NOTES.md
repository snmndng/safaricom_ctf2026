# HEAD Office

- **Category:** web
- **Points:** 250
- **Branch:** `chal/web-head-office`
- **Target:** `http://54.72.82.22:8180`
- **Status:** ✅ SOLVED

## Flag

```
safctf{e657eef1b0b097c60911f62cfe4ec61b}
```

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
