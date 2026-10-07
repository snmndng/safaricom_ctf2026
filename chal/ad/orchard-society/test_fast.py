#!/usr/bin/env python3
"""Fast focused test of most likely objectType GUID candidates."""
import requests
import hashlib

BASE = "http://54.72.82.22:8570"

resource = "record-ef1b86a30b808513"
decider_sid = "S-1-5-21-810-920-1030-1068"
decider_type = "allow"
decider_right = "ReadProperty"
decider_name = "team-a4283b27"
session_sid = "S-1-5-21-810-920-1030-1000"
session_name = "team-a4654927"

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

# Most likely GUID candidates based on Winter Pavilion pattern (MD5 hashes = 32 hex)
print("Testing top GUID candidates...")

# 1. MD5 of the allow ACE key fields
ace_key = f"{decider_sid}|{decider_type}|{decider_right}"
g = hashlib.md5(ace_key.encode()).hexdigest()
print(f"1. MD5(ace_key): {g}")
if test(f"{g}|{decider_type}|{decider_right}"): exit(0)
if test(f"{g}|{decider_sid}|{decider_right}"): exit(0)
if test(f"{decider_sid}|{g}|{decider_right}"): exit(0)

# 2. MD5 with resource
ace_key2 = f"{resource}|{decider_sid}|{decider_type}|{decider_right}"
g = hashlib.md5(ace_key2.encode()).hexdigest()
print(f"2. MD5(resource+ace): {g}")
if test(f"{g}|{decider_type}|{decider_right}"): exit(0)
if test(f"{g}|{decider_sid}|{decider_right}"): exit(0)
if test(f"{decider_sid}|{g}|{decider_right}"): exit(0)

# 3. MD5 of decider name
g = hashlib.md5(decider_name.encode()).hexdigest()
print(f"3. MD5(decider_name): {g}")
if test(f"{g}|{decider_type}|{decider_right}"): exit(0)
if test(f"{g}|{decider_sid}|{decider_right}"): exit(0)

# 4. Resource suffix (16 hex) doubled to 32
suffix = "ef1b86a30b808513"
g = suffix + suffix
print(f"4. suffix*2: {g}")
if test(f"{g}|{decider_type}|{decider_right}"): exit(0)
if test(f"{g}|{decider_sid}|{decider_right}"): exit(0)

# 5. Resource suffix padded
g = suffix + "0"*16
print(f"5. suffix+zeros: {g}")
if test(f"{g}|{decider_type}|{decider_right}"): exit(0)

# 6. Decider name hex (8 chars) padded
g = "a4283b27" + "0"*24
print(f"6. name_hex+zeros: {g}")
if test(f"{g}|{decider_type}|{decider_right}"): exit(0)

# 7. Well-known property GUIDs (schemaIDGUID) - no dashes, 32 hex
well_known = [
    "bf967a860de611d0a28500aa003049e2",  # userPrincipalName
    "bf967a9c0de611d0a28500aa003049e2",  # objectGUID
    "bf967a9a0de611d0a28500aa003049e2",  # sAMAccountName
    "bf967a9e0de611d0a28500aa003049e2",  # displayName
    "bf967a9f0de611d0a28500aa003049e2",  # givenName
    "bf967aa00de611d0a28500aa003049e2",  # sn
    "bf967aa80de611d0a28500aa003049e2",  # mail
    "bf967aaa0de611d0a28500aa003049e2",  # telephoneNumber
    "bf967a9d0de611d0a28500aa003049e2",  # member
    "5f20201079c511d090a400c04fd8d8a8",  # memberOf
]
for g in well_known:
    print(f"7. well-known: {g}")
    if test(f"{g}|{decider_type}|{decider_right}"): exit(0)
    if test(f"{g}|{decider_sid}|{decider_right}"): exit(0)

# 8. SHA256 truncated to 32
for key in [ace_key, ace_key2, resource, decider_sid, decider_name]:
    g = hashlib.sha256(key.encode()).hexdigest()[:32]
    print(f"8. SHA256_32({key[:30]}...): {g}")
    if test(f"{g}|{decider_type}|{decider_right}"): exit(0)
    if test(f"{g}|{decider_sid}|{decider_right}"): exit(0)

# 9. SHA1 truncated to 32
for key in [ace_key, ace_key2, resource, decider_sid, decider_name]:
    g = hashlib.sha1(key.encode()).hexdigest()[:32]
    print(f"9. SHA1_32({key[:30]}...): {g}")
    if test(f"{g}|{decider_type}|{decider_right}"): exit(0)
    if test(f"{g}|{decider_sid}|{decider_right}"): exit(0)

# 10. The actual resource suffix as GUID with dashes
g = "ef1b86a3-0b80-8513-0000-000000000000"
print(f"10. suffix-as-guid: {g}")
if test(f"{g}|{decider_type}|{decider_right}"): exit(0)

print("\nNo hit in focused test")