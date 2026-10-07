---
title: "Mr Beast Configuration"
ctf: "Safaricom CTF"
date: 2026-10-06
category: web
difficulty: easy
points: 150
flag_format: "safctf{...}"
author: "Strawhats"
---

# Mr Beast Configuration

> **Category:** WEB · **Points:** 150 · **Difficulty:** easy (as designed) / unsolvable (as deployed)

## Summary

The intended bug is a classic misconfigured management endpoint: `GET /config`
dumps `app.config` (including `FLAG` and the `/admin` credentials) as JSON. On
this deployment, however, `/config` **crashes unconditionally** with a
`TypeError` before emitting a single byte, because Flask's default config always
contains a `timedelta` that `jsonify` cannot serialize. The Werkzeug debugger
traceback leaks only the handler source, not the secret values, and every
alternate path (interactive console, credential brute force, header bypass) is
closed — the console's PIN counter was already burned to "exhausted" by other
players. **Broken as deployed; no flag obtainable.**

## Recon — the route map

```
Server: Werkzeug/3.1.9 Python/3.11.16   (Flask dev server, debug=True, evalex=true)
Access-Control-Allow-Origin: *
```

Fuzzing ~500 paths plus a 2016-case method/extension sweep gives the complete
surface:

| Route | Status | Notes |
|---|---|---|
| `/` | 200 | Themed "CREATOR HOUSE" landing page |
| `/hint` | 200 | `{"hint": "The crew is taking five. The next scene starts after lunch."}` |
| `/admin` | 401 | HTTP Basic (`WWW-Authenticate: Basic realm="Login Required"`) |
| `/config` | 500 | Werkzeug debugger traceback — **the intended vuln** |
| `/console` | 200 | Werkzeug interactive console (`EVALEX=true`) |

No reflection on `/` (20 params × 7 payloads), no traversal. The debug server is
wide open in theory, which is what makes the `/config` crash so frustrating.

## The intended vulnerability (recovered from the traceback)

The `/config` 500 is a debugger traceback that leaks `app.py` lines 70–80:

```python
71| @app.route('/config')
72| def config_dump():
73|     # Return the configuration (including FLAG and credentials).
74|     cfg = {k: v for k, v in app.config.items() if k.isupper()}
75|     return jsonify(cfg)       # <-- TypeError: timedelta is not JSON serializable
```

So the author's design is: `/config` leaks `FLAG` + the admin password, and
`/admin` is Basic-gated by that password.

## Why it is unsolvable as deployed

**1. `/config` crashes for everyone, every time.** `app.config` always carries
Flask's default `PERMANENT_SESSION_LIFETIME = timedelta(days=31)`. `k.isupper()`
is true for it, so it enters `cfg`. Flask's `DefaultJSONProvider._default`
handles `date`, `Decimal`, `UUID`, dataclasses and `__html__` — **not
`timedelta`** — so `jsonify` raises `TypeError` before producing output. No
Flask version serializes `timedelta`, so this is not a version-skew we can lean
on. The endpoint cannot return anything, to anyone.

**2. The traceback leaks the handler, not the values.** The debugger shows ±5
source lines around the failing line, recovering `app.py:70-80`, which contains
no secrets. The `FLAG` and password assignments live at `app.py:1-69`, out of
the visible window.

**3. The interactive console (the only RCE path) is locked and bricked.**

- `Host: localhost` satisfies `check_host_trust`, so `pinauth`/`printpin` are
  reachable — but they return `{"auth": false, "exhausted": true}`.
- The PIN is derived from `uuid.getnode()` (MAC) + `get_machine_id()`, neither
  of which is derivable remotely, so it cannot be computed.
- `_failed_pin_auth` is a shared per-process counter already `>= 10`, so
  `pin_auth` short-circuits to `exhausted = True` and never compares the supplied
  PIN. Even the *correct* PIN is rejected for the life of the process. (Brute
  force was never viable regardless: 9 digits, 10 attempts, 5 s penalty each.)

**4. `/admin` credentials are unguessable and unobtainable.** ~1,200 themed +
common credential pairs failed. No header bypass works — `X-Forwarded-For`,
`X-Real-IP`, `X-Original-URL`, `X-Rewrite-URL`, `X-Custom-IP-Authorization`,
`Client-IP`, etc. all 401.

**5. The hint is flavor.** "The crew is taking five… after lunch" matches the
landing-page copy; nothing in the app gates on time.

## Verdict

The intended solve is `GET /config` → read `FLAG`/credentials → `GET /admin`.
Step one 500s unconditionally due to an author-side Flask/JSON incompatibility,
and every alternate path is closed. **Report `/config` on port 8110 as broken to
the organizers.**

## Tools

**Used in this solve:**

- curl (route map, header-bypass matrix, Basic-auth probing)
- Python 3 (path/method fuzzing, credential spray, console PIN probing)
- the Werkzeug debugger traceback itself (source-leak oracle)

**Other tools that fit this task:**

- Burp Suite (repeater/intruder for the credential and header matrices)
- ffuf / feroxbuster (route and extension discovery)
- `werkzeug`-PIN research tooling (e.g. the public PIN-derivation PoCs), had the
  machine inputs been obtainable
- Flask source reading locally to reproduce the `timedelta` crash

## Flag

_Not obtained — `/config` crashes unconditionally and every alternate path is closed. Broken as deployed._
