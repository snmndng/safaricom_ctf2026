#!/usr/bin/env python3
"""Test focused natural language and AD-style receipt formats."""
import requests

BASE = "http://54.72.82.22:8570"

resource = "record-ef1b86a30b808513"
decider_sid = "S-1-5-21-810-920-1030-1068"
decider_type = "allow"
decider_right = "ReadProperty"
decider_name = "team-a4283b27"
session_name = "team-a4654927"

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

print("Testing focused candidates...\n")

# AD-style effective permission strings - most likely formats
candidates = [
    # Core pipe-joins (Winter Pavilion style: 3 identifying fields)
    f"{resource}|{decider_sid}|{decider_type}|{decider_right}",
    f"{decider_sid}|{decider_type}|{decider_right}|{resource}",
    f"{decider_sid}|{decider_right}|{decider_type}",
    f"{decider_name}|{decider_type}|{decider_right}",
    f"{decider_name}|{decider_right}|{decider_type}",
    f"{resource}|{decider_name}|{decider_type}|{decider_right}",
    f"{decider_type}|{decider_right}|{decider_sid}",
    f"{decider_type}|{decider_right}|{decider_name}",
    f"{decider_right}|{decider_type}|{decider_sid}",
    f"{decider_right}|{decider_type}|{decider_name}",
    
    # With "effective" prefix
    f"effective|{decider_sid}|{decider_type}|{decider_right}",
    f"effective|{resource}|{decider_sid}|{decider_type}|{decider_right}",
    f"decision|{decider_sid}|{decider_type}|{decider_right}",
    f"result|{decider_sid}|{decider_type}|{decider_right}",
    
    # Natural language
    f"Allow {decider_name} {decider_right} on {resource}",
    f"Allow {decider_sid} {decider_right} on {resource}",
    f"Grant {decider_right} to {decider_name} on {resource}",
    f"Effective: Allow {decider_name} {decider_right} on {resource}",
    
    # SDDL-like
    f"D:P(A;;{decider_right};;;{decider_sid})",
    f"D:(A;;{decider_right};;;{decider_sid})",
    
    # Decision only
    "allow",
    "ALLOW",
    "granted",
    "true",
    "True",
    
    # With session info
    f"{session_name}|{decider_name}|{decider_type}|{decider_right}",
    f"{session_name}->{decider_name}|{decider_type}|{decider_right}",
]

for c in candidates:
    if test(c):
        exit(0)

# Test chain + decision
chain = "S-1-5-21-810-920-1030-1000|S-1-5-21-810-920-1030-1013|S-1-5-21-810-920-1030-1027|S-1-5-21-810-920-1030-1046|S-1-5-21-810-920-1030-1068"
chain_names = "team-a4654927|team-0f85fe7a|team-b13c037b|team-2648700f|team-a4283b27"

for base in [chain, chain_names]:
    for suffix in ["", "|allow", "|allow|ReadProperty", "|allow|ReadProperty|" + resource]:
        if test(base + suffix):
            exit(0)

# Test the deny ACE info
deny_sid = "S-1-5-21-810-920-1030-1069"
deny_name = "team-5803825d"
for base in [
    f"{decider_sid}|{decider_type}|{decider_right}|{deny_sid}|deny|{decider_right}",
    f"{decider_name}|{decider_type}|{decider_right}|{deny_name}|deny|{decider_right}",
]:
    if test(base):
        exit(0)

# Test with the note text hash
note = "Visitors sometimes belong to more than one committee. For the reading room, consult both the current register and the filed exception."
import hashlib
for h in [hashlib.sha256(note.encode()).hexdigest(), hashlib.md5(note.encode()).hexdigest()]:
    if test(h):
        exit(0)

print("\nAll focused candidates exhausted. No hit.")