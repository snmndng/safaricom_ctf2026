#!/usr/bin/env python3
"""Fast targeted test of schema GUIDs as objectType."""
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

# Most likely schema GUIDs for ReadProperty on user/computer/group objects
# ReadProperty typically applies to specific properties
# The GUID in the ACE's ObjectType field identifies the property
schema_guids = [
    # Properties commonly used with ReadProperty
    "bf967a86-0de6-11d0-a285-00aa003049e2",  # userPrincipalName
    "bf967a9c-0de6-11d0-a285-00aa003049e2",  # objectGUID
    "bf967a9a-0de6-11d0-a285-00aa003049e2",  # sAMAccountName
    "bf967a9e-0de6-11d0-a285-00aa003049e2",  # displayName
    "bf967a9f-0de6-11d0-a285-00aa003049e2",  # givenName
    "bf967aa0-0de6-11d0-a285-00aa003049e2",  # sn
    "bf967aa8-0de6-11d0-a285-00aa003049e2",  # mail
    "bf967aaa-0de6-11d0-a285-00aa003049e2",  # telephoneNumber
    "bf967a9d-0de6-11d0-a285-00aa003049e2",  # member
    "5f202010-79c5-11d0-90a4-00c04fd8d8a8",  # memberOf
    # Class GUIDs
    "bf967a86-0de6-11d0-a285-00aa003049e2",  # user class
    "bf967a87-0de6-11d0-a285-00aa003049e2",  # computer class
    "bf967a88-0de6-11d0-a285-00aa003049e2",  # group class
    "bf967a89-0de6-11d0-a285-00aa003049e2",  # OU class
    # Extended rights
    "00299570-246d-11d0-a768-00aa006e0529",  # Reset Password / Force Change Password
    "ab721a54-1e2f-11d0-9819-00aa0040529b",  # Change Password
    # Resource-specific (from suffix ef1b86a30b808513)
    "ef1b86a3-0b80-8513-0000-000000000000",
    "ef1b86a3-0b80-8513-0000-000000000000".upper(),
    "00000000-0000-0000-ef1b-86a30b808513",
    "ef1b86a30b808513",
    "ef1b86a30b808513".upper(),
]

print(f"Testing {len(schema_guids)} GUID candidates...")

for guid in schema_guids:
    guid_nodash = guid.replace('-', '')
    
    # Primary pattern: objectType|sid|right (like guid|serviceAccount|command)
    if test(f"{guid}|{decider_sid}|{decider_right}"): exit(0)
    if test(f"{guid}|{decider_name}|{decider_right}"): exit(0)
    if test(f"{guid_nodash}|{decider_sid}|{decider_right}"): exit(0)
    if test(f"{guid_nodash}|{decider_name}|{decider_right}"): exit(0)
    
    # objectType|type|right
    if test(f"{guid}|{decider_type}|{decider_right}"): exit(0)
    if test(f"{guid_nodash}|{decider_type}|{decider_right}"): exit(0)
    
    # sid|objectType|right
    if test(f"{decider_sid}|{guid}|{decider_right}"): exit(0)
    if test(f"{decider_name}|{guid}|{decider_right}"): exit(0)
    if test(f"{decider_sid}|{guid_nodash}|{decider_right}"): exit(0)
    if test(f"{decider_name}|{guid_nodash}|{decider_right}"): exit(0)

print("No hit with primary patterns")

# Also test hashes
print("\nTesting hashes of primary patterns...")
for guid in schema_guids:
    guid_nodash = guid.replace('-', '')
    for base in [
        f"{guid}|{decider_sid}|{decider_right}",
        f"{guid_nodash}|{decider_sid}|{decider_right}",
        f"{guid}|{decider_type}|{decider_right}",
        f"{guid_nodash}|{decider_type}|{decider_right}",
    ]:
        for h in [hashlib.sha256(base.encode()).hexdigest(), hashlib.md5(base.encode()).hexdigest()]:
            if test(h): exit(0)

print("No hit with hashes either")