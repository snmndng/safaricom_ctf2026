#!/usr/bin/env python3
"""Minimal test of most likely candidates."""
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

# Most likely: the dropped GUID is MD5 of the ACE fields (32 hex chars like Winter Pavilion guid)
# Winter Pavilion guid is 32 hex chars = MD5 output
ace_key = f"{decider_sid}|{decider_type}|{decider_right}"
guid = hashlib.md5(ace_key.encode()).hexdigest()

print(f"Testing GUID from MD5(ace_key): {guid}")

# Winter Pavilion pattern: guid|serviceAccount|command
# For ACE: guid|sid|right
if test(f"{guid}|{decider_sid}|{decider_right}"):
    exit(0)
if test(f"{guid}|{decider_name}|{decider_right}"):
    exit(0)
if test(f"{guid}|{decider_type}|{decider_right}"):
    exit(0)

# Also try SHA256 truncated to 32 chars
guid2 = hashlib.sha256(ace_key.encode()).hexdigest()[:32]
print(f"Testing GUID from SHA256_32(ace_key): {guid2}")
if test(f"{guid2}|{decider_sid}|{decider_right}"):
    exit(0)
if test(f"{guid2}|{decider_name}|{decider_right}"):
    exit(0)
if test(f"{guid2}|{decider_type}|{decider_right}"):
    exit(0)

# Try with resource included
ace_key2 = f"{resource}|{decider_sid}|{decider_type}|{decider_right}"
guid3 = hashlib.md5(ace_key2.encode()).hexdigest()
print(f"Testing GUID from MD5(resource+ace_key): {guid3}")
if test(f"{guid3}|{decider_sid}|{decider_right}"):
    exit(0)
if test(f"{guid3}|{decider_name}|{decider_right}"):
    exit(0)

guid4 = hashlib.sha256(ace_key2.encode()).hexdigest()[:32]
print(f"Testing GUID from SHA256_32(resource+ace_key): {guid4}")
if test(f"{guid4}|{decider_sid}|{decider_right}"):
    exit(0)
if test(f"{guid4}|{decider_name}|{decider_right}"):
    exit(0)

# Try the resource suffix as GUID (16 hex chars -> pad to 32)
suffix = "ef1b86a30b808513"
guid5 = suffix + "0"*16
print(f"Testing GUID from resource suffix padded: {guid5}")
if test(f"{guid5}|{decider_sid}|{decider_right}"):
    exit(0)

guid6 = suffix + suffix
print(f"Testing GUID from resource suffix doubled: {guid6}")
if test(f"{guid6}|{decider_sid}|{decider_right}"):
    exit(0)

# Try the decider name as GUID (it's 8 hex chars, pad)
name_hex = "a4283b27"
guid7 = name_hex + "0"*24
print(f"Testing GUID from decider name hex padded: {guid7}")
if test(f"{guid7}|{decider_sid}|{decider_right}"):
    exit(0)

print("No hit")