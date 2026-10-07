#!/usr/bin/env python3
"""Targeted receipt candidates for Orchard Society based on 'dropped field' hypothesis."""
import hashlib
import requests

BASE = "http://54.72.82.22:8570"

# Core data
resource = "record-ef1b86a30b808513"
decider_sid = "S-1-5-21-810-920-1030-1068"
decider_type = "allow"
decider_right = "ReadProperty"
decider_name = "team-a4283b27"
session_sid = "S-1-5-21-810-920-1030-1000"
session_name = "team-a4654927"

# Chain
chain = [
    "S-1-5-21-810-920-1030-1000",  # team-a4654927
    "S-1-5-21-810-920-1030-1013",  # team-0f85fe7a
    "S-1-5-21-810-920-1030-1027",  # team-b13c037b
    "S-1-5-21-810-920-1030-1046",  # team-2648700f
    "S-1-5-21-810-920-1030-1068",  # team-a4283b27 (decider)
]
chain_names = ["team-a4654927", "team-0f85fe7a", "team-b13c037b", "team-2648700f", "team-a4283b27"]

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

print("Testing targeted candidates...\n")

# The Winter Pavilion pattern: three identifying fields of the deciding object
# For GPO link: guid|serviceAccount|command
# For ACE: what are the three identifying fields?
# In AD, an ACE has: Sid, AceType, AccessMask, Flags, ObjectType, InheritedObjectType
# The export has: sid, type, right
# Dropped field is likely ObjectType (a GUID for the property)

# Hypothesis 1: The receipt is sid|type|right|objectType (4 fields)
# But we don't know objectType. Let's try some guesses.

# Hypothesis 2: The receipt includes the resource
candidates = [
    # Resource + ACE fields
    f"{resource}|{decider_sid}|{decider_type}|{decider_right}",
    f"{decider_sid}|{decider_type}|{decider_right}|{resource}",
    
    # ACE fields only (3 fields - Winter Pavilion pattern)
    f"{decider_sid}|{decider_type}|{decider_right}",
    
    # With name instead of SID
    f"{decider_name}|{decider_type}|{decider_right}",
    
    # Chain of SIDs (5 SIDs)
    "|".join(chain),
    ":".join(chain),
    
    # Chain of names
    "|".join(chain_names),
    ":".join(chain_names),
    
    # Chain with decider type/right
    f"{'|'.join(chain)}|{decider_type}|{decider_right}",
    
    # Resource + chain
    f"{resource}|{'|'.join(chain)}",
    
    # Just the resource
    resource,
    
    # Just the decider SID
    decider_sid,
    decider_name,
    
    # Decision
    "allow",
    "ALLOW",
    "granted",
    
    # Session info
    session_sid,
    session_name,
]

# Common AD attribute GUIDs (schemaIDGUIDs) - the "objectType" for ReadProperty
# These are well-known GUIDs for common attributes
common_attr_guids = [
    # userPrincipalName
    "bf967a86-0de6-11d0-a285-00aa003049e2",
    # objectGUID
    "bf967a9c-0de6-11d0-a285-00aa003049e2",
    # sAMAccountName
    "bf967a9a-0de6-11d0-a285-00aa003049e2",
    # displayName
    "bf967a9e-0de6-11d0-a285-00aa003049e2",
    # givenName
    "bf967a9f-0de6-11d0-a285-00aa003049e2",
    # sn
    "bf967aa0-0de6-11d0-a285-00aa003049e2",
    # mail
    "bf967aa8-0de6-11d0-a285-00aa003049e2",
    # telephoneNumber
    "bf967aaa-0de6-11d0-a285-00aa003049e2",
    # member
    "bf967a9d-0de6-11d0-a285-00aa003049e2",
    # memberOf
    "5f202010-79c5-11d0-90a4-00c04fd8d8a8",
    # Common control access rights
    # Reset Password
    "00299570-246d-11d0-a768-00aa006e0529",
    # Change Password
    "ab721a54-1e2f-11d0-9819-00aa0040529b",
]

# Test with hypothetical objectType GUIDs
print("Testing with hypothetical objectType GUIDs...")
for guid in common_attr_guids:
    # 4-field join: sid|type|right|objectType
    if test(f"{decider_sid}|{decider_type}|{decider_right}|{guid}", f"objType={guid}"):
        exit(0)
    # 4-field join: resource|sid|type|right|objectType
    if test(f"{resource}|{decider_sid}|{decider_type}|{decider_right}|{guid}", f"objType={guid}"):
        exit(0)
    # 3-field join: objectType|type|right (like guid|serviceAccount|command)
    if test(f"{guid}|{decider_type}|{decider_right}", f"objType={guid}"):
        exit(0)
    # 3-field join: sid|objectType|right
    if test(f"{decider_sid}|{guid}|{decider_right}", f"objType={guid}"):
        exit(0)

# Test resource-based GUID (from resource ID)
print("\nTesting resource-derived GUIDs...")
resource_suffix = "ef1b86a30b808513"  # 16 hex chars
# Try to form a GUID from it
guids_from_resource = [
    f"ef1b86a3-0b80-8513-0000-000000000000",
    f"ef1b86a3-0b80-8513-0000-000000000000".upper(),
    f"00000000-0000-0000-0000-ef1b86a30b80",  # reversed
    f"ef1b86a30b808513",  # raw
]
for guid in guids_from_resource:
    if test(f"{decider_sid}|{decider_type}|{decider_right}|{guid}", f"resourceGuid={guid}"):
        exit(0)
    if test(f"{guid}|{decider_type}|{decider_right}", f"resourceGuid={guid}"):
        exit(0)

# Test hashes of the core join
print("\nTesting hashes...")
core_join = f"{decider_sid}|{decider_type}|{decider_right}"
for h in [hashlib.sha256(core_join.encode()).hexdigest(),
          hashlib.md5(core_join.encode()).hexdigest(),
          hashlib.sha1(core_join.encode()).hexdigest()]:
    if test(h, f"hash of {core_join}"):
        exit(0)

core_join2 = f"{resource}|{decider_sid}|{decider_type}|{decider_right}"
for h in [hashlib.sha256(core_join2.encode()).hexdigest(),
          hashlib.md5(core_join2.encode()).hexdigest(),
          hashlib.sha1(core_join2.encode()).hexdigest()]:
    if test(h, f"hash of {core_join2}"):
        exit(0)

# Test safctf{} wrappers
print("\nTesting safctf{} wrappers...")
for base in [core_join, core_join2, "allow", "ALLOW", decider_sid, resource]:
    if test(f"safctf{{{base}}}", f"wrapper {base}"):
        exit(0)

# Test all the basic candidates
print("\nTesting basic candidates...")
for c in candidates:
    if test(c, "basic"):
        exit(0)

# Test key=value forms
print("\nTesting key=value forms...")
kv_candidates = [
    f"sid={decider_sid},type={decider_type},right={decider_right}",
    f"resource={resource},sid={decider_sid},type={decider_type},right={decider_right}",
    f"objectSid={decider_sid};aceType={decider_type};accessRight={decider_right}",
    f"sid={decider_sid}|type={decider_type}|right={decider_right}",
    f"resource={resource}|sid={decider_sid}|type={decider_type}|right={decider_right}",
]
for c in kv_candidates:
    if test(c, "key=value"):
        exit(0)

# Test UPN/Domain forms
print("\nTesting UPN/Domain forms...")
upn_candidates = [
    f"{decider_name}@orchard.test",
    f"ORCHARD\\{decider_name}",
    f"ORCHARD\\{decider_sid}",
    f"{session_name}@orchard.test",
    f"ORCHARD\\{session_name}",
]
for c in upn_candidates:
    if test(c, "UPN"):
        exit(0)

# Test deny ACE info
print("\nTesting deny ACE combinations...")
deny_sid = "S-1-5-21-810-920-1030-1069"
deny_type = "deny"
deny_right = "ReadProperty"
deny_name = "team-5803825d"
both = [
    f"{decider_sid}|{decider_type}|{decider_right}|{deny_sid}|{deny_type}|{deny_right}",
    f"{resource}|{decider_sid}|{decider_type}|{decider_right}|{deny_sid}|{deny_type}|{deny_right}",
]
for c in both:
    if test(c, "both ACEs"):
        exit(0)

# Test with RID only (last part of SID)
print("\nTesting RID-only forms...")
rids = [s.split('-')[-1] for s in chain]
if test("|".join(rids), "chain RIDs"):
    exit(0)
if test(f"{rids[-1]}|{decider_type}|{decider_right}", "decider RID"):
    exit(0)

# Test with the note text
print("\nTesting curator note variants...")
note = "Visitors sometimes belong to more than one committee. For the reading room, consult both the current register and the filed exception."
for h in [hashlib.sha256(note.encode()).hexdigest(), hashlib.md5(note.encode()).hexdigest()]:
    if test(h, "note hash"):
        exit(0)

print("\nAll targeted candidates exhausted. No hit.")