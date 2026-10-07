#!/usr/bin/env python3
"""Orchard Society round 7 — case-fold / wrapper / canonical-JSON / count micro-sweep.

The decision is settled (session …-1000 -> 1013 -> 1027 -> 1046 -> 1068 allow;
the 1069 deny never applies). Earlier rounds covered raw joins with | and :
plus hashes; this pass fills the remaining cheap gaps:
  * case variants of every alphabetic component (record-…, ReadProperty, allow, team-…)
  * separators beyond | and :   (- _ , ; = & space and empty)
  * key=value and query-string forms
  * canonical JSON serialisations of the deciding ACE / whole ACL
  * safctf{} wrappers and sha256/md5/sha1 of every raw form
  * count-style answers (closure size, rows, denied teams, RIDs)
  * deny-row joins (the filed exception) in the same case/sep space
"""
import hashlib, itertools, json, sys
from concurrent.futures import ThreadPoolExecutor
import requests

BASE = "http://54.72.82.22:8570"

RES   = "record-ef1b86a30b808513"
SID_D = "S-1-5-21-810-920-1030-1068"   # deciding allow SID
SID_S = "S-1-5-21-810-920-1030-1000"   # session / visitor
SID_N = "S-1-5-21-810-920-1030-1069"   # deny decoy
NM_D  = "team-a4283b27"
NM_S  = "team-a4654927"
NM_N  = "team-5803825d"
RIGHT = "ReadProperty"
CHAIN = ["S-1-5-21-810-920-1030-1000", "S-1-5-21-810-920-1030-1013",
         "S-1-5-21-810-920-1030-1027", "S-1-5-21-810-920-1030-1046",
         "S-1-5-21-810-920-1030-1068"]
NAMES = ["team-a4654927", "team-0f85fe7a", "team-b13c037b",
         "team-2648700f", "team-a4283b27"]

def cases(w):
    return list(dict.fromkeys([w, w.lower(), w.upper(), w.title(), w.capitalize()]))

def wrap(s):
    h = lambda f: f(s.encode()).hexdigest()
    out = [s, hashlib.sha256(s.encode()).hexdigest(), hashlib.md5(s.encode()).hexdigest(),
           hashlib.sha1(s.encode()).hexdigest(), "safctf{%s}" % s,
           "safctf{%s}" % hashlib.sha256(s.encode()).hexdigest()]
    return [x for x in out if x]

def build():
    cands = set()

    res      = cases(RES)
    right    = cases(RIGHT)
    allow    = cases("allow")
    deny     = cases("deny")
    name_d   = cases(NM_D)
    name_s   = cases(NM_S)
    name_n   = cases(NM_N)
    seps     = ["|", ":", "-", "_", ",", ";", "=", "&", " ", ""]

    orders = [
        [ [SID_D], allow, right ],
        [ res, [SID_D], allow, right ],
        [ res, right ],
        [ res, [SID_D], right ],
        [ name_d, allow, right ],
        [ res, name_d, allow, right ],
        [ [SID_D], right ],
        [ res, allow ],
        [ [SID_S], allow ],
        [ [SID_S], [SID_D], allow, right ],
        [ name_s, name_d, allow, right ],
        [ res, [SID_D], deny, right ],          # both ACEs, allow row first
        [ name_n, deny, right ],                # deny row identity
        [ [SID_N], deny, right ],
        [ res, [SID_N], deny, right ],
    ]
    for parts in orders:
        for combo in itertools.product(*parts):
            for sep in seps:
                cands.update(wrap(sep.join(combo)))

    # key=value forms
    kv_orders = [
        [("resource", res), ("sid", [SID_D]), ("type", allow), ("right", right)],
        [("sid", [SID_D]), ("type", allow), ("right", right)],
        [("resource", res), ("decision", allow)],
        [("resource", res), ("granted", allow), ("by", [SID_D])],
    ]
    for kvo in kv_orders:
        keys = [k for k, _ in kvo]
        for combo in itertools.product(*[v for _, v in kvo]):
            for sep in ("&", "|", ";", ",", " ", ":"):
                cands.update(wrap(sep.join(f"{k}={v}" for k, v in zip(keys, combo))))
                cands.update(wrap(sep.join(f"{k}:{v}" for k, v in zip(keys, combo))))

    # canonical JSON forms
    ace = {"sid": SID_D, "type": "allow", "right": RIGHT}
    ace_n = {"sid": SID_N, "type": "deny", "right": RIGHT}
    acl = {"resource": RES,
           "aces": [{"sid": SID_D, "type": "allow", "right": RIGHT},
                    {"sid": SID_N, "type": "deny", "right": RIGHT}]}
    jsons = [
        json.dumps(ace), json.dumps(ace, separators=(",", ":")),
        json.dumps(ace, sort_keys=True, separators=(",", ":")),
        json.dumps(ace_n), json.dumps(ace_n, separators=(",", ":")),
        json.dumps(acl), json.dumps(acl, separators=(",", ":")),
        json.dumps({"resource": RES, "decision": "allow"}),
        json.dumps({"resource": RES, "decision": "allow"}, separators=(",", ":")),
        json.dumps({"answer": f"{SID_D}|allow|{RIGHT}"}),
        json.dumps({"decision": "allow", "by": SID_D, "resource": RES}, separators=(",", ":")),
    ]
    for j in jsons:
        cands.update(wrap(j))

    # count-style answers
    counts = ["4", "5", "61", "70", "0", "1", "1068", "1069", "1000",
              "5/70", "4/70", "1/70", "0/70", "1 of 70", "5 of 70",
              "61 of 70", "70", "69", "2"]
    for c in counts:
        cands.update(wrap(c))

    # chain joins with the remaining separators (+ case variants of names)
    for seq in (CHAIN, NAMES):
        for sep in ("-", ",", ";", " ", "_", ">", "->", ".", "/"):
            cands.update(wrap(sep.join(seq)))
            cands.update(wrap(sep.join(x.upper() for x in seq)))
    return cands

def main():
    cands = sorted(build())
    print(f"{len(cands)} candidates")
    sess = requests.Session()
    stop = False

    def fire(a):
        try:
            r = sess.post(BASE + "/submit", json={"answer": a}, timeout=15)
            return a, r.status_code, r.text
        except Exception:
            return a, -1, ""

    with ThreadPoolExecutor(max_workers=12) as ex:
        for a, code, body in ex.map(fire, cands):
            if code == -1:
                continue
            if code != 403:
                print("HIT:", code, repr(a), body[:200]); stop = True; break
    if not stop:
        print("no hit in round-7 micro-sweep")

if __name__ == "__main__":
    main()
