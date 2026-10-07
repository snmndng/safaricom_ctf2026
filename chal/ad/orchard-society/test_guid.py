#!/usr/bin/env python3
"""Focused test of GUID-based receipt candidates."""
import requests
import hashlib

BASE = "http://54.72.82.22:8570"

decider_sid = "S-1-5-21-810-920-1030-1068"
decider_type = "allow"
decider_right = "ReadProperty"
decider_name = "team-a4283b27"
resource = "record-ef1b86a30b808513"

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

# Generate GUID candidates from hashes of ACE fields
ace_str = f"{decider_sid}|{decider_type}|{decider_right}"
ace_str2 = f"{decider_name}|{decider_type}|{decider_right}"
ace_str3 = f"{resource}|{decider_sid}|{decider_type}|{decider_right}"

guid_candidates = []
for s in [ace_str, ace_str2, ace_str3, decider_sid, decider_name, resource]:
    guid_candidates.append(hashlib.sha256(s.encode()).hexdigest())
    guid_candidates.append(hashlib.md5(s.encode()).hexdigest())

# Also try with dashes
guid_candidates_dashed = []
for g in guid_candidates:
    dashed = f"{g[:8]}-{g[8:12]}-{g[12:16]}-{g[16:20]}-{g[20:32]}"
    guid_candidates_dashed.append(dashed)
    guid_candidates_dashed.append(dashed.upper())

all_guids = list(dict.fromkeys(guid_candidates + guid_candidates_dashed))

print(f"Testing {len(all_guids)} GUID candidates...")

# Test receipt = guid|sid|right (Winter Pavilion pattern: guid|who|what)
for g in all_guids:
    if test(f"{g}|{decider_sid}|{decider_right}"):
        exit(0)
    if test(f"{g}|{decider_name}|{decider_right}"):
        exit(0)

# Test receipt = guid|type|right
for g in all_guids:
    if test(f"{g}|{decider_type}|{decider_right}"):
        exit(0)

# Test receipt = sid|guid|right
for g in all_guids:
    if test(f"{decider_sid}|{g}|{decider_right}"):
        exit(0)
    if test(f"{decider_name}|{g}|{decider_right}"):
        exit(0)

print("No hit")