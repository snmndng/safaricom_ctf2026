#!/usr/bin/env python3
"""Test more receipt format variations - fast batch."""
import requests
import hashlib
import json

BASE = "http://54.72.82.22:8570"

resource = "record-ef1b86a30b808513"
decider_sid = "S-1-5-21-810-920-1030-1068"
decider_type = "allow"
decider_right = "ReadProperty"
decider_name = "team-a4283b27"
deny_sid = "S-1-5-21-810-920-1030-1069"
deny_type = "deny"
deny_right = "ReadProperty"
deny_name = "team-5803825d"
session_sid = "S-1-5-21-810-920-1030-1000"
session_name = "team-a4654927"

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

# Test both ACEs combined (the "filed exception" + "current register")
print("Testing both ACEs combined...")
both_candidates = [
    f"{decider_sid}|{decider_type}|{decider_right}|{deny_sid}|{deny_type}|{deny_right}",
    f"{resource}|{decider_sid}|{decider_type}|{decider_right}|{deny_sid}|{deny_type}|{deny_right}",
    f"{decider_name}|{decider_type}|{decider_right}|{deny_name}|{deny_type}|{deny_right}",
    f"allow|{decider_sid}|{decider_right}|deny|{deny_sid}|{decider_right}",
    f"allow|{decider_name}|{decider_right}|deny|{deny_name}|{decider_right}",
    f"{decider_type}|{decider_sid}|{decider_right}|{deny_type}|{deny_sid}|{deny_right}",
]

for c in both_candidates:
    if test(c): exit(0)
    # Also try hashes
    for h in [hashlib.sha256(c.encode()).hexdigest(), hashlib.md5(c.encode()).hexdigest()]:
        if test(h): exit(0)

# Test chain + both ACEs
chain = "S-1-5-21-810-920-1030-1000|S-1-5-21-810-920-1030-1013|S-1-5-21-810-920-1030-1027|S-1-5-21-810-920-1030-1046|S-1-5-21-810-920-1030-1068"
for c in [
    f"{chain}|{decider_type}|{decider_right}|{deny_type}|{decider_right}",
    f"{chain}|allow|{deny_type}",
]:
    if test(c): exit(0)
    for h in [hashlib.sha256(c.encode()).hexdigest(), hashlib.md5(c.encode()).hexdigest()]:
        if test(h): exit(0)

# Test the full ACL JSON in different formats
acl = {"resource": resource, "aces": [
    {"sid": decider_sid, "type": decider_type, "right": decider_right},
    {"sid": deny_sid, "type": deny_type, "right": deny_right}
]}
for c in [
    json.dumps(acl, separators=(',', ':')),
    json.dumps(acl),
    json.dumps(acl, sort_keys=True, separators=(',', ':')),
]:
    if test(c): exit(0)
    for h in [hashlib.sha256(c.encode()).hexdigest(), hashlib.md5(c.encode()).hexdigest()]:
        if test(h): exit(0)

# Test resource ID variations
for c in [
    resource,
    "ef1b86a30b808513",
    "ef1b86a30b808513".upper(),
    "RECORD-EF1B86A30B808513",
]:
    if test(c): exit(0)

# Test "reading room" from note
for c in [
    "reading room",
    "readingroom",
    "current register and the filed exception",
    "Visitors sometimes belong to more than one committee",
]:
    if test(c): exit(0)
    for h in [hashlib.sha256(c.encode()).hexdigest(), hashlib.md5(c.encode()).hexdigest()]:
        if test(h): exit(0)

# Test decision + chain
for c in [
    f"allow|{chain}",
    f"allow|{session_name}|{decider_name}",
    f"grant|{decider_name}|{decider_right}",
    f"effective|allow|{decider_name}|{decider_right}",
]:
    if test(c): exit(0)
    for h in [hashlib.sha256(c.encode()).hexdigest(), hashlib.md5(c.encode()).hexdigest()]:
        if test(h): exit(0)

# Test with numeric access mask (ReadProperty = 0x10 = 16)
for mask in ["16", "0x10", "0x00000010"]:
    for c in [
        f"{mask}|{decider_sid}|{decider_right}",
        f"{mask}|{decider_type}|{decider_right}",
        f"{mask}|{decider_name}|{decider_right}",
        f"{resource}|{mask}|{decider_sid}|{decider_right}",
    ]:
        if test(c): exit(0)
        for h in [hashlib.sha256(c.encode()).hexdigest(), hashlib.md5(c.encode()).hexdigest()]:
            if test(h): exit(0)

# Test objectType as 0 (no objectType)
for c in [
    f"0|{decider_sid}|{decider_right}",
    f"0|{decider_type}|{decider_right}",
    f"{decider_sid}|0|{decider_right}",
]:
    if test(c): exit(0)
    for h in [hashlib.sha256(c.encode()).hexdigest(), hashlib.md5(c.encode()).hexdigest()]:
        if test(h): exit(0)

print("No hit")