#!/usr/bin/env python3
"""Fast SDDL test."""
import requests
import hashlib

BASE = "http://54.72.82.22:8570"

decider_sid = "S-1-5-21-810-920-1030-1068"
decider_type = "allow"
decider_right = "ReadProperty"
decider_name = "team-a4283b27"
deny_sid = "S-1-5-21-810-920-1030-1069"

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

print("Testing key SDDL candidates...\n")

# Most likely SDDL forms
sddl_candidates = [
    f"D:(A;;RP;;;{decider_sid})",
    f"D:P(A;;RP;;;{decider_sid})",
    f"(A;;RP;;;{decider_sid})",
    f"A;;RP;;;{decider_sid}",
    f"D:(A;;RP;;;{decider_sid})(D;;RP;;;{deny_sid})",
    f"D:P(A;;RP;;;{decider_sid})(D;;RP;;;{deny_sid})",
]

for s in sddl_candidates:
    if test(s): exit(0)
    for h in [hashlib.sha256(s.encode()).hexdigest(), hashlib.md5(s.encode()).hexdigest()]:
        if test(h): exit(0)

# Key flag values
for flag in ["0", "CI", "OI", "CI|OI", "ID", "0x1", "0x2", "0x3"]:
    s = f"D:(A;{flag};RP;;;{decider_sid})"
    if test(s): exit(0)
    for h in [hashlib.sha256(s.encode()).hexdigest(), hashlib.md5(s.encode()).hexdigest()]:
        if test(h): exit(0)

# Deny ACE
for f in [
    f"{deny_sid}|deny|{decider_right}",
    f"{decider_sid}|allow|{decider_right}|{deny_sid}|deny|{decider_right}",
]:
    if test(f): exit(0)
    for h in [hashlib.sha256(f.encode()).hexdigest(), hashlib.md5(f.encode()).hexdigest()]:
        if test(h): exit(0)

print("No hit")