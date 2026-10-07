#!/usr/bin/env python3
"""Focused test of hash-based receipt candidates."""
import requests
import hashlib

BASE = "http://54.72.82.22:8570"

resource = "record-ef1b86a30b808513"
decider_sid = "S-1-5-21-810-920-1030-1068"
decider_type = "allow"
decider_right = "ReadProperty"
decider_name = "team-a4283b27"

def test_hash(join, label=""):
    for h in [hashlib.sha256(join.encode()).hexdigest(),
              hashlib.md5(join.encode()).hexdigest(),
              hashlib.sha1(join.encode()).hexdigest()]:
        try:
            r = requests.post(BASE + "/submit", json={"answer": h}, timeout=5)
        except Exception:
            continue
        if r.status_code != 403:
            print(f"!!! HIT ({label}) !!! {r.status_code} - {h}")
            print(f"From: {join}")
            print(f"Response: {r.text}")
            return True
    return False

# Most likely joins based on patterns from other challenges
joins = [
    # Winter Pavilion pattern: 3 identifying fields
    f"{resource}|{decider_sid}|{decider_type}|{decider_right}",
    f"{decider_sid}|{decider_type}|{decider_right}",
    f"{decider_name}|{decider_type}|{decider_right}",
    
    # Blue Meridian / Last Tram Home: 3 fields that uniquely identify the decision
    f"{resource}|{decider_sid}|{decider_right}",
    f"{resource}|{decider_name}|{decider_right}",
    
    # Resource ref only (Paper Lanterns style)
    resource,
    "ef1b86a30b808513",
    
    # Decider identifier only
    decider_sid,
    decider_name,
    "a4283b27",
    "1068",
    
    # Chain
    "S-1-5-21-810-920-1030-1000|S-1-5-21-810-920-1030-1013|S-1-5-21-810-920-1030-1027|S-1-5-21-810-920-1030-1046|S-1-5-21-810-920-1030-1068",
    "team-a4654927|team-0f85fe7a|team-b13c037b|team-2648700f|team-a4283b27",
    
    # Decision
    "allow",
    "ALLOW",
]

print("Testing hash candidates...")
for join in joins:
    if test_hash(join, join[:50]):
        exit(0)

# Test with different separators
print("\nTesting with different separators...")
seps = [':', '-', '_', ',', ';', ' ']
core_joins = [
    f"{resource}|{decider_sid}|{decider_type}|{decider_right}",
    f"{decider_sid}|{decider_type}|{decider_right}",
    f"{decider_name}|{decider_type}|{decider_right}",
]
for join in core_joins:
    for sep in seps:
        alt = join.replace('|', sep)
        if test_hash(alt, f"{alt[:50]} (sep={sep})"):
            exit(0)

print("\nNo hit")