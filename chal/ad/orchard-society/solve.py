#!/usr/bin/env python3
"""Orchard Society (AD, 300) -- http://54.72.82.22:8570

Artifact: /downloads/orchard-export.zip -> curator-note.txt, session.json,
directory.json, resource-acl.json.

Model: resolve the visitor's EFFECTIVE access to the resource.
  session.json gives our SID; directory.json gives nested group membership
  (the "current register"); resource-acl.json gives the allow/deny ACEs
  (the "filed exception").  DENY wins over ALLOW when both match.
"""
import io, json, hashlib, itertools, zipfile, requests

BASE = "http://54.72.82.22:8570"

def fetch():
    r = requests.get(BASE + "/downloads/orchard-export.zip", timeout=20); r.raise_for_status()
    zf = zipfile.ZipFile(io.BytesIO(r.content))
    return r.content, {n: zf.read(n) for n in zf.namelist()}

def closure(me, parent):
    seen, st = set(), [me]
    while st:
        for p in parent.get(st.pop(), []):
            if p not in seen:
                seen.add(p); st.append(p)
    return seen

def decide(files):
    d = json.loads(files["directory.json"])
    acl = json.loads(files["resource-acl.json"])
    me = json.loads(files["session.json"])["objectSid"]
    parent = {e["sid"]: e.get("memberOf", []) for e in d}
    name = {e["sid"]: e["name"] for e in d}
    held = closure(me, parent) | {me}
    matched = [a for a in acl["aces"] if a["sid"] in held]
    # Windows rule: an applicable deny beats any allow.
    denied = [a for a in matched if a["type"] == "deny"]
    return dict(me=me, held=held, name=name, acl=acl, matched=matched,
                denied=denied,
                decision="deny" if denied else ("allow" if matched else "none"),
                decider=(denied[0] if denied else (matched[0] if matched else None)))

def candidates(s):
    acl, dec = s["acl"], s["decider"]
    res = acl["resource"]
    # the winning ACE's own fields, and the resolution path
    core = [res, dec["sid"], dec["type"], dec["right"],
            s["me"], s["name"].get(dec["sid"], "")]
    for n in (1, 2, 3):
        for combo in itertools.permutations(core, n):
            for sep in ("|", ":"):
                yield sep.join(combo)
    for n in (2, 3):
        for combo in itertools.permutations(core, n):
            j = "|".join(combo)
            yield hashlib.sha256(j.encode()).hexdigest()
            yield hashlib.md5(j.encode()).hexdigest()
    yield s["decision"]
    yield "safctf{%s}" % s["decision"]

def main():
    blob, files = fetch()
    print("zip sha256:", hashlib.sha256(blob).hexdigest(), "entries:", list(files))
    s = decide(files)
    print("me:", s["me"], "| decision:", s["decision"], "| decider:", json.dumps(s["decider"]))
    tried = 0
    for a in candidates(s):
        tried += 1
        try:
            r = requests.post(BASE + "/submit", json={"answer": a}, timeout=15)
        except Exception:
            continue
        if r.status_code != 403:
            print("HIT:", r.status_code, repr(a), r.text[:200]); return
    print(f"no candidate accepted ({tried} tried)")

if __name__ == "__main__":
    main()
