# Mr Beast Configuration

- **Category:** web
- **Points:** 150
- **Branch:** `chal/web-mr-beast-configuration`
- **Target:** `http://54.72.82.22:8110`
- **Status:** BLOCKED — target appears unsolvable as deployed (see Verdict)

## Fingerprint

```
Server: Werkzeug/3.1.9 Python/3.11.16   (Flask dev server, debug=True, evalex=True)
Access-Control-Allow-Origin: *
Access-Control-Allow-Headers: *
```

Complete route map (verified by fuzzing ~500 paths + 2016-case method/extension sweep):

| Route | Status | Notes |
|---|---|---|
| `/` | 200 | Themed landing page ("CREATOR HOUSE", creator-studio theme) |
| `/hint` | 200 | `{"hint": "The crew is taking five. The next scene starts after lunch."}` |
| `/admin` | 401 | `WWW-Authenticate: Basic realm="Login Required"`, body `Unauthorized` |
| `/config` | 500 | Werkzeug debugger traceback — **the intended vuln** |
| `/console` | 200 | Werkzeug interactive console shell page (`EVALEX=true`) |

No other routes exist. No SSTI/reflection on `/` (probed 20 params × 7 payloads, zero reflection).
No path traversal (`/static/../../app.py` etc. all 404).

## The intended vulnerability (confirmed from leaked source)

The `/config` 500 page is a Werkzeug debugger traceback that leaks `app.py` lines 70–80.

```python
70| # Oops - exposing configuration via an endpoint is the intentional vulnerability
71| @app.route('/config')
72| def config_dump():
73|     # Return the configuration (including FLAG and credentials). This simulates a misconfigured management endpoint.
74|     cfg = {k: v for k, v in app.config.items() if k.isupper()}
75|     return jsonify(cfg)          # <-- TypeError: Object of type timedelta is not JSON serializable
77| # A small "hint" endpoint to help players (but not the full solution)
78| @app.route('/hint')
79| def hint():
80|     return jsonify({
```

So the author's design is: `/config` dumps `app.config` (which holds `FLAG` + admin credentials),
`/admin` is Basic-gated with a password that `/config` was meant to reveal.

## Why it is unsolvable as deployed

**1. `/config` crashes unconditionally.** `app.config` always contains Flask's default
`PERMANENT_SESSION_LIFETIME = timedelta(days=31)`. `k.isupper()` is true for it, so it lands in `cfg`.
Flask's `DefaultJSONProvider._default` (`flask/json/provider.py:121`) handles `date`, `Decimal`,
`UUID`, dataclasses and `__html__` — **not `timedelta`** — so `jsonify` raises `TypeError`
before emitting a single byte. No Flask version handles `timedelta`; this is not a version skew
we can exploit. The endpoint cannot return anything, to anyone.

**2. The traceback leaks only the handler, not the values.** The debugger shows ±5 source lines
around the failing line, so we recover `app.py:70-80` — which contains no credentials. The `FLAG`
and password assignments live at `app.py:1-69`, unreachable.

**3. The Werkzeug interactive console (the only RCE path) is locked and permanently bricked.**

```python
# werkzeug/debug/__init__.py
def check_pin_trust(self, environ):
    if self.pin is None: return True
    if self._failed_pin_auth.value >= 10: return False
    ...
```

- `Host: localhost` **does** satisfy `check_host_trust`, so `pinauth`/`printpin` are reachable
  (they return `{"auth": false, "exhausted": true}` instead of a 400 `SecurityError`) — but the
  secret `8BxKGknnrhSjhxO49wEM` was already known from `debugger.js`, so this adds nothing.
- The PIN is **not `off`** (so `check_pin_trust` is not trivially True) and is derived from
  `uuid.getnode()` (MAC) + `get_machine_id()` — both unknown remotely, so it cannot be computed.
- `_failed_pin_auth` is already `>= 10` (`"exhausted": true`) — a **shared, per-process counter**
  that other players burned. Once exhausted, `pin_auth` never even compares the supplied PIN:

```python
elif self._failed_pin_auth.value >= 10:   # short-circuits before the comparison
    exhausted = True
```

  So even the *correct* PIN would be rejected for the lifetime of this process. Brute force was
  never viable anyway (9 digits, 10 attempts, 5 s sleep per failure).

**4. `/admin` credentials are unguessable and unobtainable.** ~1,200 themed + common
username/password pairs failed. No header-based auth bypass works:
`X-Forwarded-For`, `X-Real-IP`, `X-Originating-IP`, `X-Original-URL`, `X-Rewrite-URL`,
`X-Forwarded-Host`, `X-Custom-IP-Authorization`, `X-Remote-Addr`, `Client-IP` — all 401.
`OPTIONS` returns 200/empty; `POST`/`PUT`/`TRACE` return 405.

**5. The hint is flavor, not a bypass.** "The crew is taking five. The next scene starts after
lunch." matches the landing-page copy ("late lunches", "one more take before sunset") — both are
creator-studio theming. Nothing in the app gates on time or on a "five".

## Verdict

The challenge is broken on this deployment. The intended solution is
`GET /config` → read `FLAG`/credentials → `GET /admin` with Basic auth. Step one 500s
unconditionally due to an author-side Flask/JSON incompatibility, and every alternate path
(debugger console, credential brute force, header bypass, extra routes) is closed.

**Recommended action:** report `/config` on port 8110 as broken to the CTF organizers.

## Flag

Not obtained.
