#!/usr/bin/env python3
"""Test more GUID candidates for objectType - focusing on zero GUID and resource-based."""
import requests
import hashlib

BASE = "http://54.72.82.22:8570"

resource = "record-ef1b86a30b808513"
decider_sid = "S-1-5-21-810-920-1030-1068"
decider_type = "allow"
decider_right = "ReadProperty"
decider_name = "team-a4283b27"

def test(ans):
    try:
        r = requests.post(BASE + "/submit", json={"answer": ans}, timeout=5)
    except Exception:
        return False
    if r.status_code != 403:
        print(f"!!! HIT !!! {r.status_code} - {ans}")
        print(f"Response: {r.text}")
        return True
    return False

print("Testing zero GUID and resource-derived GUIDs...\n")

# 1. Zero GUID (no objectType in ACE)
zero_guids = [
    "00000000-0000-0000-0000-000000000000",
    "00000000000000000000000000000000",
    "0",
    "0000000000000000",
]

for g in zero_guids:
    print(f"  Zero GUID: {g}")
    if test(f"{g}|{decider_type}|{decider_right}"): exit(0)
    if test(f"{g}|{decider_sid}|{decider_right}"): exit(0)
    if test(f"{decider_sid}|{g}|{decider_right}"): exit(0)

# 2. Resource suffix as GUID with various completions
suffix = "ef1b86a30b808513"  # 16 hex chars = 64 bits
# GUID is 128 bits = 32 hex chars
# Try completing with zeros, with hash, with fixed patterns
completions = [
    "000000000000",           # pad to 32
    "0000000000000000",       # pad to 32 (different)
    suffix,                   # double
    hashlib.sha256(suffix.encode()).hexdigest()[:16],  # hash
    hashlib.md5(suffix.encode()).hexdigest()[:16],     # md5
    "00000000000000000000000000000000",  # all zeros
]

for comp in completions:
    g = suffix + comp
    g_dashed = f"{g[:8]}-{g[8:12]}-{g[12:16]}-{g[16:20]}-{g[20:32]}"
    print(f"  Resource GUID: {g_dashed}")
    if test(f"{g_dashed}|{decider_type}|{decider_right}"): exit(0)
    if test(f"{g}|{decider_type}|{decider_right}"): exit(0)
    if test(f"{g_dashed}|{decider_sid}|{decider_right}"): exit(0)

# 3. Resource suffix as first part of GUID
for prefix in ["ef1b86a3-0b80-8513", "ef1b86a30b808513"]:
    for suffix_part in [
        "0000-0000-000000000000",
        "1111-1111-111111111111",
        "ffff-ffff-ffffffffffff",
        "abcd-ef12-1234567890ab",
    ]:
        g = f"{prefix}-{suffix_part}"
        print(f"  Resource GUID variant: {g}")
        if test(f"{g}|{decider_type}|{decider_right}"): exit(0)

# 4. Well-known GUIDs for AD schema classes (not attributes)
# Common object class schemaIDGUIDs
class_guids = [
    "bf967a860de611d0a28500aa003049e2",  # user
    "bf967a870de611d0a28500aa003049e2",  # organizationalUnit
    "bf967a880de611d0a28500aa003049e2",  # group
    "bf967a890de611d0a28500aa003049e2",  # domain
    "bf967a8a0de611d0a28500aa003049e2",  # computer
    "bf967a8b0de611d0a28500aa003049e2",  # container
    "bf967a8c0de611d0a28500aa003049e2",  # domainDNS
    "bf967a8d0de611d0a28500aa003049e2",  # trustedDomain
    "bf967a8e0de611d0a28500aa003049e2",  # foreignSecurityPrincipal
    "bf967a8f0de611d0a28500aa003049e2",  # securityObject
]

for g in class_guids:
    g_dashed = f"{g[:8]}-{g[8:12]}-{g[12:16]}-{g[16:20]}-{g[20:32]}"
    print(f"  Class GUID: {g_dashed}")
    if test(f"{g_dashed}|{decider_type}|{decider_right}"): exit(0)
    if test(f"{g}|{decider_type}|{decider_right}"): exit(0)

# 5. The decider SID's RID as GUID
rid = "1068"
for g in [
    f"00000000-0000-0000-0000-00000000{int(rid):04x}",
    f"00000000-0000-0000-0000-0000{int(rid):08x}",
    f"00000000-0000-0000-0000-00000000{int(rid):04x}",
    f"00000000-0000-0000-{int(rid):04x}-000000000000",
]:
    print(f"  RID GUID: {g}")
    if test(f"{g}|{decider_type}|{decider_right}"): exit(0)

# 6. Try the resource ID as-is (record-ef1b86a30b808513) as the "guid" field
print(f"\n  Testing resource as guid: {resource}")
if test(f"{resource}|{decider_type}|{decider_right}"): exit(0)
if test(f"{resource}|{decider_sid}|{decider_right}"): exit(0)

# 7. SHA256 of resource as GUID
g = hashlib.sha256(resource.encode()).hexdigest()[:32]
g_dashed = f"{g[:8]}-{g[8:12]}-{g[12:16]}-{g[16:20]}-{g[20:32]}"
print(f"  SHA256(resource) as GUID: {g_dashed}")
if test(f"{g_dashed}|{decider_type}|{decider_right}"): exit(0)
if test(f"{g}|{decider_type}|{decider_right}"): exit(0)

# 8. SHA256 of decider SID as GUID
g = hashlib.sha256(decider_sid.encode()).hexdigest()[:32]
g_dashed = f"{g[:8]}-{g[8:12]}-{g[12:16]}-{g[16:20]}-{g[20:32]}"
print(f"  SHA256(decider_sid) as GUID: {g_dashed}")
if test(f"{g_dashed}|{decider_type}|{decider_right}"): exit(0)

print("\nNo hit")