#!/usr/bin/env python3
"""Test numeric dropped field hypotheses."""
import requests

BASE = "http://54.72.82.22:8570"

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

# Numeric dropped field candidates
numeric_fields = [
    '0', '1', '2', '3',  # inheritance flags
    '16', '32', '48',    # access masks (ReadProperty=16, WriteProperty=32)
    '0x10', '0x20',      # hex access masks
    '1068', '1069', '1000',  # RIDs
]

print("Testing numeric dropped field...")
for num in numeric_fields:
    # num|sid|right
    if test(f"{num}|{decider_sid}|{decider_right}"):
        exit(0)
    if test(f"{num}|{decider_name}|{decider_right}"):
        exit(0)
    # num|type|right
    if test(f"{num}|{decider_type}|{decider_right}"):
        exit(0)
    # sid|num|right
    if test(f"{decider_sid}|{num}|{decider_right}"):
        exit(0)
    # num|sid|type
    if test(f"{num}|{decider_sid}|{decider_type}"):
        exit(0)

print("No hit")