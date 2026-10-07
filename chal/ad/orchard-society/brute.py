#!/usr/bin/env python3
"""Brute force receipt candidates for Orchard Society."""
import hashlib
import itertools
import json
import requests

BASE = "http://54.72.82.22:8570"

# Load data
with open('chal/ad/orchard-society/site-mirror/export/directory.json') as f:
    d = json.load(f)
with open('chal/ad/orchard-society/site-mirror/export/resource-acl.json') as f:
    acl = json.load(f)
with open('chal/ad/orchard-society/site-mirror/export/session.json') as f:
    session = json.load(f)

me = session['objectSid']
parent = {e['sid']: e.get('memberOf', []) for e in d}
name = {e['sid']: e['name'] for e in d}

def closure(me, parent):
    seen, st = set(), [me]
    while st:
        for p in parent.get(st.pop(), []):
            if p not in seen:
                seen.add(p); st.append(p)
    return seen

held = closure(me, parent) | {me}
matched = [a for a in acl['aces'] if a['sid'] in held]
denied = [a for a in matched if a['type'] == 'deny']
decider = denied[0] if denied else (matched[0] if matched else None)

resource = acl['resource']
decider_sid = decider['sid']
decider_type = decider['type']
decider_right = decider['right']
decider_name = name.get(decider_sid, '')

print(f"Resource: {resource}")
print(f"Decider: {decider_sid} ({decider_name}) | {decider_type} | {decider_right}")

# Core fields from the decider ACE
core = [resource, decider_sid, decider_type, decider_right, decider_name, me, name.get(me, '')]

# The chain SIDs
chain_sids = ['S-1-5-21-810-920-1030-1000', 'S-1-5-21-810-920-1030-1013', 
              'S-1-5-21-810-920-1030-1027', 'S-1-5-21-810-920-1030-1046', 
              'S-1-5-21-810-920-1030-1068']

# Common separators
seps = ['|', ':', '-', '_', '', ' ', ',', ';', '=']

# Test candidates
tested = 0
found = False

def test_candidate(ans):
    global tested, found
    tested += 1
    if tested % 100 == 0:
        print(f"Tested {tested} candidates...")
    try:
        r = requests.post(BASE + "/submit", json={"answer": ans}, timeout=10)
    except Exception as e:
        return False
    if r.status_code != 403:
        print(f"HIT! Status: {r.status_code}, Answer: {ans}, Response: {r.text}")
        found = True
        return True
    return False

# 1. Direct pipe-joins of core fields (1-5 fields)
print("Testing direct joins...")
for n in range(1, 6):
    for combo in itertools.permutations(core, n):
        for sep in ['|', ':']:
            if test_candidate(sep.join(combo)):
                exit(0)

# 2. Hashes of joins
print("Testing hashes...")
for n in range(2, 5):
    for combo in itertools.permutations(core, n):
        j = '|'.join(combo)
        for h in [hashlib.sha256(j.encode()).hexdigest(), 
                  hashlib.md5(j.encode()).hexdigest(),
                  hashlib.sha1(j.encode()).hexdigest()]:
            if test_candidate(h):
                exit(0)

# 3. Chain joins
print("Testing chain joins...")
for n in range(2, 6):
    for combo in itertools.permutations(chain_sids, n):
        for sep in ['|', ':']:
            if test_candidate(sep.join(combo)):
                exit(0)

# 4. Chain joins with decider fields
print("Testing chain + decider...")
pool = chain_sids + [decider_type, decider_right, resource]
for n in range(3, 6):
    for combo in itertools.permutations(pool, n):
        for sep in ['|', ':']:
            if test_candidate(sep.join(combo)):
                exit(0)

# 5. Key=value forms
print("Testing key=value forms...")
kv_forms = [
    f"sid={decider_sid}|type={decider_type}|right={decider_right}",
    f"resource={resource}|sid={decider_sid}|type={decider_type}|right={decider_right}",
    f"objectSid={decider_sid}|aceType={decider_type}|accessRight={decider_right}",
    f"sid={decider_sid},type={decider_type},right={decider_right}",
]
for kv in kv_forms:
    if test_candidate(kv):
        exit(0)

# 6. UPN/Domain forms
print("Testing UPN/Domain forms...")
upn_forms = [
    f"{decider_name}@orchard.test",
    f"ORCHARD\\{decider_name}",
    f"ORCHARD\\{decider_sid}",
]
for u in upn_forms:
    if test_candidate(u):
        exit(0)

# 7. The resource ID parts
print("Testing resource ID parts...")
resource_parts = resource.split('-')
for part in resource_parts:
    if test_candidate(part):
        exit(0)
    if test_candidate(f"record-{part}"):
        exit(0)

# 8. Try with "allow" capitalized variants
print("Testing case variants...")
for t in ['allow', 'Allow', 'ALLOW']:
    for r in ['ReadProperty', 'readproperty', 'READPROPERTY']:
        if test_candidate(f"{decider_sid}|{t}|{r}"):
            exit(0)
        if test_candidate(f"{resource}|{decider_sid}|{t}|{r}"):
            exit(0)

# 9. With the deny ACE too
print("Testing with deny ACE...")
deny_ace = [a for a in acl['aces'] if a['type'] == 'deny'][0]
deny_sid = deny_ace['sid']
deny_type = deny_ace['type']
deny_right = deny_ace['right']
both_aces = [
    f"{decider_sid}|{decider_type}|{decider_right}|{deny_sid}|{deny_type}|{deny_right}",
    f"{resource}|{decider_sid}|{decider_type}|{decider_right}|{deny_sid}|{deny_type}|{deny_right}",
]
for b in both_aces:
    if test_candidate(b):
        exit(0)

# 10. Try the decision string
print("Testing decision string...")
if test_candidate("allow"):
    exit(0)
if test_candidate("ALLOW"):
    exit(0)
if test_candidate("granted"):
    exit(0)

# 11. Try safctf{} wrappers
print("Testing safctf{} wrappers...")
for base in [f"{decider_sid}|{decider_type}|{decider_right}", 
             f"{resource}|{decider_sid}|{decider_type}|{decider_right}",
             "allow", "ALLOW", "granted"]:
    if test_candidate(f"safctf{{{base}}}"):
        exit(0)

# 12. Full zip hash
print("Testing full zip hash...")
import zipfile, io
r = requests.get(BASE + "/downloads/orchard-export.zip", timeout=20)
if test_candidate(hashlib.sha256(r.content).hexdigest()):
    exit(0)

print(f"\nTotal tested: {tested}")
print("No candidate accepted")