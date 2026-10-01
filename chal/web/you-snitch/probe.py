#!/usr/bin/env python3
import sys, requests
T = "http://54.72.82.22:8140/lookup.php"

def q(name):
    r = requests.get(T, params={"name": name}, timeout=20)
    body = r.text
    marker = "<h1>Newsroom records</h1>"
    i = body.find(marker)
    tail = body[i+len(marker):] if i >= 0 else body
    return r.status_code, tail

if __name__ == "__main__":
    for name in sys.argv[1:]:
        code, tail = q(name)
        print(f"[{code}] {name!r} => {tail[:300]}")
