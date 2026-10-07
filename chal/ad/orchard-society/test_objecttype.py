#!/usr/bin/env python3
"""Test objectType GUID hypotheses for Orchard Society."""
import hashlib
import requests

BASE = "http://54.72.82.22:8570"

resource = "record-ef1b86a30b808513"
decider_sid = "S-1-5-21-810-920-1030-1068"
decider_type = "allow"
decider_right = "ReadProperty"
decider_name = "team-a4283b27"

resource_suffix = "ef1b86a30b808513"  # 16 hex chars

def test(ans, label=""):
    try:
        r = requests.post(BASE + "/submit", json={"answer": ans}, timeout=10)
    except Exception as e:
        print(f"  ERROR: {e}")
        return False
    if r.status_code != 403:
        print(f"!!! HIT ({label}) !!! Status: {r.status_code}, Answer: {ans}")
        print(f"Response: {r.text}")
        return True
    return False

# Hypothesis: objectType is a GUID derived from resource_suffix
# resource_suffix = ef1b86a30b808513 (16 hex chars)
# GUID format: 8-4-4-4-12 = 32 hex chars

print("Testing objectType GUID hypotheses based on resource suffix...")

# The resource suffix could be the first 16 chars of a GUID
# Try padding with zeros
guids = [
    f"ef1b86a3-0b80-8513-0000-000000000000",
    f"ef1b86a3-0b80-8513-0000-000000000000".upper(),
    f"00000000-0000-0000-ef1b-86a30b808513",  # last 16
    f"ef1b86a30b808513",  # raw 16 chars
    f"ef1b86a30b808513".upper(),
]

# Also try SHA256 of resource suffix
resource_hash = hashlib.sha256(resource_suffix.encode()).hexdigest()
guids.append(f"{resource_hash[:8]}-{resource_hash[8:12]}-{resource_hash[12:16]}-{resource_hash[16:20]}-{resource_hash[20:32]}")
guids.append(f"{resource_hash[:8]}-{resource_hash[8:12]}-{resource_hash[12:16]}-{resource_hash[16:20]}-{resource_hash[20:32]}".upper())

# SHA256 of full resource
full_hash = hashlib.sha256(resource.encode()).hexdigest()
guids.append(f"{full_hash[:8]}-{full_hash[8:12]}-{full_hash[12:16]}-{full_hash[16:20]}-{full_hash[20:32]}")

# SHA256 of decider SID
sid_hash = hashlib.sha256(decider_sid.encode()).hexdigest()
guids.append(f"{sid_hash[:8]}-{sid_hash[8:12]}-{sid_hash[12:16]}-{sid_hash[16:20]}-{sid_hash[20:32]}")

# SHA256 of decider name
name_hash = hashlib.sha256(decider_name.encode()).hexdigest()
guids.append(f"{name_hash[:8]}-{name_hash[8:12]}-{name_hash[12:16]}-{name_hash[16:20]}-{name_hash[20:32]}")

# SHA256 of chain join
chain = "S-1-5-21-810-920-1030-1000|S-1-5-21-810-920-1030-1013|S-1-5-21-810-920-1030-1027|S-1-5-21-810-920-1030-1046|S-1-5-21-810-920-1030-1068"
chain_hash = hashlib.sha256(chain.encode()).hexdigest()
guids.append(f"{chain_hash[:8]}-{chain_hash[8:12]}-{chain_hash[12:16]}-{chain_hash[16:20]}-{chain_hash[20:32]}")

# Deduplicate
guids = list(dict.fromkeys(guids))

for guid in guids:
    print(f"  Trying objectType: {guid}")
    # Format: objectType|type|right (like guid|serviceAccount|command)
    if test(f"{guid}|{decider_type}|{decider_right}", f"objType|type|right={guid}"):
        exit(0)
    # Format: sid|objectType|right
    if test(f"{decider_sid}|{guid}|{decider_right}", f"sid|objType|right={guid}"):
        exit(0)
    # Format: objectType|sid|type|right
    if test(f"{guid}|{decider_sid}|{decider_type}|{decider_right}", f"objType|sid|type|right={guid}"):
        exit(0)
    # Format: sid|type|right|objectType
    if test(f"{decider_sid}|{decider_type}|{decider_right}|{guid}", f"sid|type|right|objType={guid}"):
        exit(0)
    # Format: resource|objectType|type|right
    if test(f"{resource}|{guid}|{decider_type}|{decider_right}", f"resource|objType|type|right={guid}"):
        exit(0)

print("\nTesting objectType from decider SID RID...")
# The decider SID ends with -1068. Maybe objectType is derived from that?
rid = "1068"
for fmt in [
    f"00000000-0000-0000-0000-{rid.zfill(12)}",
    f"00000000-0000-0000-0000-{rid.zfill(12)}".upper(),
    f"{rid.zfill(8)}-0000-0000-0000-000000000000",
]:
    if test(f"{fmt}|{decider_type}|{decider_right}", f"objType from RID={fmt}"):
        exit(0)

print("\nTesting objectType from session SID RID...")
rid = "1000"
for fmt in [
    f"00000000-0000-0000-0000-{rid.zfill(12)}",
    f"{rid.zfill(8)}-0000-0000-0000-000000000000",
]:
    if test(f"{fmt}|{decider_type}|{decider_right}", f"objType from session RID={fmt}"):
        exit(0)

print("\nTesting objectType as hash of (resource + decider_sid)...")
combined = resource + decider_sid
h = hashlib.sha256(combined.encode()).hexdigest()
guid = f"{h[:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:32]}"
if test(f"{guid}|{decider_type}|{decider_right}", f"objType from hash={guid}"):
    exit(0)

print("\nTesting objectType as hash of (decider_sid + decider_right)...")
combined = decider_sid + decider_right
h = hashlib.sha256(combined.encode()).hexdigest()
guid = f"{h[:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:32]}"
if test(f"{guid}|{decider_type}|{decider_right}", f"objType from hash={guid}"):
    exit(0)

print("\nAll objectType hypotheses exhausted. No hit.")