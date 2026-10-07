#!/usr/bin/env python3
"""Deep test of objectType GUID hypotheses for Orchard Society."""
import requests
import hashlib
import itertools

BASE = "http://54.72.82.22:8570"

resource = "record-ef1b86a30b808513"
decider_sid = "S-1-5-21-810-920-1030-1068"
decider_type = "allow"
decider_right = "ReadProperty"
decider_name = "team-a4283b27"
session_sid = "S-1-5-21-810-920-1030-1000"
session_name = "team-a4654927"
deny_sid = "S-1-5-21-810-920-1030-1069"
deny_name = "team-5803825d"
note = "Visitors sometimes belong to more than one committee. For the reading room, consult both the current register and the filed exception."

def test(ans):
    try:
        r = requests.post(BASE + "/submit", json={"answer": ans}, timeout=10)
    except Exception as e:
        print(f"  ERROR: {e}")
        return False
    if r.status_code != 403:
        print(f"!!! HIT !!! {r.status_code} - {ans}")
        print(f"Response: {r.text}")
        return True
    return False

# ============================================================
# Generate objectType GUID candidates (32 hex chars = MD5 size)
# ============================================================
guid_candidates = set()

# 1. MD5 hashes of various combinations
inputs = [
    resource,
    decider_sid,
    decider_name,
    f"{decider_sid}|{decider_type}|{decider_right}",
    f"{decider_name}|{decider_type}|{decider_right}",
    f"{resource}|{decider_sid}|{decider_type}|{decider_right}",
    f"{resource}|{decider_name}|{decider_type}|{decider_right}",
    f"{resource}|{decider_sid}|{decider_right}",
    f"{resource}|{decider_name}|{decider_right}",
    session_sid,
    session_name,
    deny_sid,
    deny_name,
    note,
    "ef1b86a30b808513",
    "team-a4283b27",
    "team-a4654927",
    "orchard",
    "orchard.test",
    "orchard society",
    "reading room",
    "current register",
    "filed exception",
]

for inp in inputs:
    guid_candidates.add(hashlib.md5(inp.encode()).hexdigest())
    guid_candidates.add(hashlib.sha256(inp.encode()).hexdigest()[:32])
    guid_candidates.add(hashlib.sha1(inp.encode()).hexdigest()[:32])

# 2. Resource suffix variations (16 hex chars -> 32)
suffix = "ef1b86a30b808513"
guid_candidates.add(suffix + "0"*16)
guid_candidates.add("0"*16 + suffix)
guid_candidates.add(suffix + suffix)
guid_candidates.add(suffix.upper() + "0"*16)
guid_candidates.add("0"*16 + suffix.upper())

# 3. Decider name (8 hex chars) variations
name_hex = "a4283b27"
guid_candidates.add(name_hex + "0"*24)
guid_candidates.add("0"*24 + name_hex)
guid_candidates.add(name_hex * 4)

# 4. Chain-based
chain = "S-1-5-21-810-920-1030-1000|S-1-5-21-810-920-1030-1013|S-1-5-21-810-920-1030-1027|S-1-5-21-810-920-1030-1046|S-1-5-21-810-920-1030-1068"
guid_candidates.add(hashlib.md5(chain.encode()).hexdigest())
guid_candidates.add(hashlib.sha256(chain.encode()).hexdigest()[:32])

# 5. Well-known AD property GUIDs (schemaIDGUIDs) - common ones
well_known = [
    "bf967a860de611d0a28500aa003049e2",  # userPrincipalName
    "bf967a9c0de611d0a28500aa003049e2",  # objectGUID
    "bf967a9a0de611d0a28500aa003049e2",  # sAMAccountName
    "bf967a9e0de611d0a28500aa003049e2",  # displayName
    "bf967a9f0de611d0a28500aa003049e2",  # givenName
    "bf967aa00de611d0a28500aa003049e2",  # sn
    "bf967aa80de611d0a28500aa003049e2",  # mail
    "bf967aaa0de611d0a28500aa003049e2",  # telephoneNumber
    "bf967a9d0de611d0a28500aa003049e2",  # member
    "5f20201079c511d090a400c04fd8d8a8",  # memberOf
    "00299570246d11d0a76800aa006e0529",  # Reset Password
    "ab721a541e2f11d0981900aa0040529b",  # Change Password
]
guid_candidates.update(well_known)

# 6. Resource suffix as GUID parts (with dashes, no dashes)
# ef1b86a3-0b80-8513-XXXX-XXXXXXXXXXXX
for prefix in ["ef1b86a30b808513", "ef1b86a3-0b80-8513"]:
    for suffix_part in ["000000000000", "000000000000".upper()]:
        guid_candidates.add(prefix + suffix_part)

print(f"Testing {len(guid_candidates)} GUID candidates...")

# ============================================================
# Test patterns: Winter Pavilion used guid|serviceAccount|command
# For ACE, likely patterns:
# ============================================================
patterns = [
    # objectType|type|right  (direct analog: guid|serviceAccount|command)
    lambda g: f"{g}|{decider_type}|{decider_right}",
    lambda g: f"{g}|{decider_type}|{decider_right}|{resource}",
    # objectType|sid|right
    lambda g: f"{g}|{decider_sid}|{decider_right}",
    lambda g: f"{g}|{decider_name}|{decider_right}",
    # sid|objectType|right
    lambda g: f"{decider_sid}|{g}|{decider_right}",
    lambda g: f"{decider_name}|{g}|{decider_right}",
    # resource|objectType|type|right
    lambda g: f"{resource}|{g}|{decider_type}|{decider_right}",
    # objectType|sid|type|right
    lambda g: f"{g}|{decider_sid}|{decider_type}|{decider_right}",
    lambda g: f"{g}|{decider_name}|{decider_type}|{decider_right}",
]

tested = 0
for g in sorted(guid_candidates):
    for pattern_fn in patterns:
        ans = pattern_fn(g)
        if test(ans):
            exit(0)
        tested += 1
        if tested % 5000 == 0:
            print(f"  Tested {tested} candidates...")

print(f"\nTotal tested: {tested}")
print("No hit")