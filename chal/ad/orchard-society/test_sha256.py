#!/usr/bin/env python3
"""Test SHA256 of pipe-joins (Blue Meridian / Last Tram Home pattern)."""
import requests
import hashlib

BASE = "http://54.72.82.22:8570"

resource = "record-ef1b86a30b808513"
decider_sid = "S-1-5-21-810-920-1030-1068"
decider_type = "allow"
decider_right = "ReadProperty"
decider_name = "team-a4283b27"

def test_hash(join):
    h = hashlib.sha256(join.encode()).hexdigest()
    try:
        r = requests.post(BASE + "/submit", json={"answer": h}, timeout=5)
    except Exception:
        return False
    if r.status_code != 403:
        print(f"!!! HIT !!! {r.status_code} - {h}")
        print(f"From: {join}")
        print(f"Response: {r.text}")
        return True
    return False

# All plausible 3-field joins for SHA256
joins = [
    # resource, sid, right (like venue_ref|event_ref|UTC_date)
    f"{resource}|{decider_sid}|{decider_right}",
    f"{resource}|{decider_name}|{decider_right}",
    
    # resource, sid, type
    f"{resource}|{decider_sid}|{decider_type}",
    f"{resource}|{decider_name}|{decider_type}",
    
    # sid, type, right (ACE identifying fields)
    f"{decider_sid}|{decider_type}|{decider_right}",
    f"{decider_name}|{decider_type}|{decider_right}",
    
    # resource, type, right
    f"{resource}|{decider_type}|{decider_right}",
    
    # chain, resource, right
    f"S-1-5-21-810-920-1030-1000|S-1-5-21-810-920-1030-1013|S-1-5-21-810-920-1030-1027|S-1-5-21-810-920-1030-1046|S-1-5-21-810-920-1030-1068|{resource}|{decider_right}",
    
    # resource only
    resource,
    "ef1b86a30b808513",
    
    # decider only
    decider_sid,
    decider_name,
    "a4283b27",
    "1068",
    
    # decision
    "allow",
    "ALLOW",
    "granted",
]

print("Testing SHA256 of joins...")
for join in joins:
    if test_hash(join):
        exit(0)

# Also try with different separators
print("\nTesting with different separators...")
core_joins = [
    f"{resource}|{decider_sid}|{decider_right}",
    f"{decider_sid}|{decider_type}|{decider_right}",
    f"{decider_name}|{decider_type}|{decider_right}",
]
for join in core_joins:
    for sep in [':', '-', '_', ',', ';', ' ']:
        alt = join.replace('|', sep)
        if test_hash(alt):
            exit(0)

print("\nNo hit")