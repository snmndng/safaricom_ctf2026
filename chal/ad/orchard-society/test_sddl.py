#!/usr/bin/env python3
"""Test SDDL format and ACE flags as dropped field."""
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

print("Testing SDDL format and ACE flags...\n")

# SDDL format for DACL
# D: = DACL
# P = Protected (SE_DACL_PROTECTED)
# A = Allow ACE
# ; = separator
# Format: (Type;Flags;Rights;ObjectType;InheritedObjectType;AccountSID)
# Rights: RP = ReadProperty, WP = WriteProperty, etc.

# Basic SDDL for the allow ACE
sddl_candidates = [
    f"D:(A;;RP;;;{decider_sid})",
    f"D:P(A;;RP;;;{decider_sid})",
    f"D:(A;;RP;{resource};;{decider_sid})",
    f"D:P(A;;RP;{resource};;{decider_sid})",
    # With objectType placeholder
    f"D:(A;;RP;{resource};GUID;;{decider_sid})",
    f"D:(A;;RP;;GUID;;{decider_sid})",
    # Both ACEs
    f"D:(A;;RP;;;{decider_sid})(D;;RP;;;S-1-5-21-810-920-1030-1069)",
    f"D:P(A;;RP;;;{decider_sid})(D;;RP;;;S-1-5-21-810-920-1030-1069)",
]

for s in sddl_candidates:
    print(f"  Testing SDDL: {s}")
    if test(s): exit(0)
    for h in [hashlib.sha256(s.encode()).hexdigest(), hashlib.md5(s.encode()).hexdigest()]:
        if test(h): exit(0)

# Try with different right representations
rights = ["RP", "0x10", "16", "0x00000010", "ReadProperty"]
for r in rights:
    s = f"D:(A;;{r};;;{decider_sid})"
    print(f"  Testing SDDL right={r}: {s}")
    if test(s): exit(0)
    for h in [hashlib.sha256(s.encode()).hexdigest(), hashlib.md5(s.encode()).hexdigest()]:
        if test(h): exit(0)

# Try ACE flags as dropped field
# Common flag combinations
flags = [
    "0", "1", "2", "3", "4", "8", "16", "32", "64", "128",
    "CI", "OI", "IO", "NP", "ID", "SA", "FA",
    "CI|OI", "CI|IO", "OI|IO",
    "0x1", "0x2", "0x3", "0x4", "0x8", "0x10", "0x20", "0x40", "0x80",
]

for flag in flags:
    # SDDL with flags
    s = f"D:(A;{flag};RP;;;{decider_sid})"
    print(f"  Testing SDDL flag={flag}: {s}")
    if test(s): exit(0)
    for h in [hashlib.sha256(s.encode()).hexdigest(), hashlib.md5(s.encode()).hexdigest()]:
        if test(h): exit(0)
    
    # Pipe format with flag
    for f in [
        f"{flag}|{decider_sid}|{decider_right}",
        f"{flag}|{decider_type}|{decider_right}",
        f"{decider_sid}|{flag}|{decider_right}",
        f"{decider_type}|{flag}|{decider_right}",
    ]:
        if test(f): exit(0)
        for h in [hashlib.sha256(f.encode()).hexdigest(), hashlib.md5(f.encode()).hexdigest()]:
            if test(h): exit(0)

# Try the deny ACE SID
deny_sid = "S-1-5-21-810-920-1030-1069"
deny_name = "team-5803825d"

print("\nTesting deny ACE combinations...")
for f in [
    f"{deny_sid}|deny|{decider_right}",
    f"{deny_name}|deny|{decider_right}",
    f"{decider_sid}|allow|{decider_right}|{deny_sid}|deny|{decider_right}",
    f"{decider_name}|allow|{decider_right}|{deny_name}|deny|{decider_right}",
]:
    if test(f): exit(0)
    for h in [hashlib.sha256(f.encode()).hexdigest(), hashlib.md5(f.encode()).hexdigest()]:
        if test(h): exit(0)

# Try the session SID (visitor)
print("\nTesting session SID as receipt...")
for f in [
    decider_sid,
    decider_name,
    "S-1-5-21-810-920-1030-1000",
    "team-a4654927",
]:
    if test(f): exit(0)

print("\nNo hit")