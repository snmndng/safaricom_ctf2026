#!/usr/bin/env python3
"""Test all hash variations for potential dropped GUID."""
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

# Input strings to hash
inputs = [
    f"{resource}|{decider_sid}|{decider_type}|{decider_right}",
    f"{decider_sid}|{decider_type}|{decider_right}",
    f"{decider_name}|{decider_type}|{decider_right}",
    f"{resource}|{decider_sid}|{decider_right}",
    f"{resource}|{decider_name}|{decider_right}",
    f"{decider_sid}|{decider_right}",
    f"{decider_name}|{decider_right}",
    decider_sid,
    decider_name,
    resource,
    "ef1b86a30b808513",
    "team-a4283b27",
    "allow",
    "ReadProperty",
]

# Hash functions
hash_funcs = [
    ("md5", lambda x: hashlib.md5(x.encode()).hexdigest()),
    ("sha256", lambda x: hashlib.sha256(x.encode()).hexdigest()),
    ("sha256_32", lambda x: hashlib.sha256(x.encode()).hexdigest()[:32]),
    ("sha1", lambda x: hashlib.sha1(x.encode()).hexdigest()),
    ("sha1_32", lambda x: hashlib.sha1(x.encode()).hexdigest()[:32]),
]

print(f"Testing {len(inputs)} inputs × {len(hash_funcs)} hash functions = {len(inputs)*len(hash_funcs)} GUID candidates...")

for inp in inputs:
    for name, hfunc in hash_funcs:
        guid = hfunc(inp)
        # Test guid|sid|right (Winter Pavilion pattern)
        if test(f"{guid}|{decider_sid}|{decider_right}"):
            exit(0)
        if test(f"{guid}|{decider_name}|{decider_right}"):
            exit(0)
        # Test guid|type|right
        if test(f"{guid}|{decider_type}|{decider_right}"):
            exit(0)
        # Test sid|guid|right
        if test(f"{decider_sid}|{guid}|{decider_right}"):
            exit(0)

print("No hit")