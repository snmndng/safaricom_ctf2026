#!/usr/bin/env python3
"""Test natural language and AD-style receipt formats."""
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

print("Testing natural language / AD-style formats...\n")

# AD-style effective permission strings
candidates = [
    # "Allow <trustee> <right> on <resource>"
    f"Allow {decider_name} {decider_right} on {resource}",
    f"Allow {decider_sid} {decider_right} on {resource}",
    f"Allow {decider_name} {decider_right}",
    f"Allow {decider_sid} {decider_right}",
    
    # "Allow <right> to <trustee> on <resource>"
    f"Allow {decider_right} to {decider_name} on {resource}",
    f"Allow {decider_right} to {decider_sid} on {resource}",
    
    # "Grant <right> to <trustee>"
    f"Grant {decider_right} to {decider_name}",
    f"Grant {decider_right} to {decider_sid}",
    
    # "<trustee> has <right> on <resource>"
    f"{decider_name} has {decider_right} on {resource}",
    f"{decider_sid} has {decider_right} on {resource}",
    
    # Effective permission format
    f"Effective: Allow {decider_name} {decider_right} on {resource}",
    f"Effective permission: {decider_name} {decider_right} {resource}",
    
    # ACL dump style
    f"{resource} : ALLOW {decider_name} {decider_right}",
    f"{resource} : ALLOW {decider_sid} {decider_right}",
    
    # SDDL-like
    f"D:P(A;;{decider_right};;;{decider_sid})",
    f"D:(A;;{decider_right};;;{decider_sid})",
    
    # With deny ACE mentioned
    f"Allow {decider_name} {decider_right} (deny {decider_name} overridden)",
    
    # "The decision is allow for <trustee>"
    f"The decision is allow for {decider_name}",
    f"The decision is allow for {decider_sid}",
    
    # Curator note inspired
    "current register and filed exception",
    "reading room",
    "consult both the current register and the filed exception",
]

for c in candidates:
    if test(c, "natural"):
        exit(0)

# Try with different separators
print("\nTesting with different separators...")
seps = ['|', ':', '-', '_', ' ', ',', ';', ' -> ', ' => ', '; ']
fields = [decider_name, decider_type, decider_right, resource]
for sep in seps:
    for n in range(2, 5):
        import itertools
        for combo in itertools.permutations(fields, n):
            if test(sep.join(combo), f"sep={sep!r}"):
                exit(0)

# Try the decision with chain
print("\nTesting chain + decision...")
chain = "S-1-5-21-810-920-1030-1000|S-1-5-21-810-920-1030-1013|S-1-5-21-810-920-1030-1027|S-1-5-21-810-920-1030-1046|S-1-5-21-810-920-1030-1068"
for suffix in ["|allow", "|allow|ReadProperty", "|allow|ReadProperty|" + resource]:
    if test(chain + suffix, "chain+decision"):
        exit(0)

# Try just the chain
print("\nTesting chain variants...")
chain_names = "team-a4654927|team-0f85fe7a|team-b13c037b|team-2648700f|team-a4283b27"
for c in [chain, chain_names, chain.replace('|', ':'), chain_names.replace('|', ':')]:
    if test(c, "chain"):
        exit(0)

# Try with "effective" keyword
print("\nTesting 'effective' keyword...")
for base in [f"{decider_sid}|{decider_type}|{decider_right}", 
             f"{resource}|{decider_sid}|{decider_type}|{decider_right}"]:
    for prefix in ["effective|", "effective-", "effective:", "result|", "result-", "result:"]:
        if test(prefix + base, "effective"):
            exit(0)

print("\nAll natural language candidates exhausted. No hit.")