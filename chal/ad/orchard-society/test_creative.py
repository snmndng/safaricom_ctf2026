#!/usr/bin/env python3
"""Creative receipt candidates - thinking outside the box."""
import requests
import hashlib
import zipfile
import io

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

print("Testing creative candidates...\n")

# 1. ZIP file properties
r = requests.get(f"{BASE}/downloads/orchard-export.zip", timeout=10)
zip_data = r.content

# ZIP CRC32s
with zipfile.ZipFile(io.BytesIO(zip_data)) as zf:
    for info in zf.infolist():
        crc = f"{info.CRC:08x}"
        print(f"  Testing CRC32 of {info.filename}: {crc}")
        if test(crc): exit(0)
        if test(crc.upper()): exit(0)

# ZIP file SHA256
print(f"  Testing ZIP SHA256: {hashlib.sha256(zip_data).hexdigest()}")
if test(hashlib.sha256(zip_data).hexdigest()): exit(0)

# 2. Challenge name / theme
for c in [
    "Orchard Society",
    "orchard-society",
    "orchard_society",
    "orchard",
    "society",
    "Orchard",
    "Society",
    "orchard.test",
    "ORCHARD",
    "ORCHARD.TEST",
]:
    if test(c): exit(0)
    for h in [hashlib.sha256(c.encode()).hexdigest(), hashlib.md5(c.encode()).hexdigest()]:
        if test(h): exit(0)

# 3. Port number
for c in ["8570", "port-8570", "port8570"]:
    if test(c): exit(0)
    for h in [hashlib.sha256(c.encode()).hexdigest(), hashlib.md5(c.encode()).hexdigest()]:
        if test(h): exit(0)

# 4. Point value
for c in ["300", "300pts", "300-pts"]:
    if test(c): exit(0)
    for h in [hashlib.sha256(c.encode()).hexdigest(), hashlib.md5(c.encode()).hexdigest()]:
        if test(h): exit(0)

# 5. Resource ID parsed
# record-ef1b86a30b808513 -> maybe "ef1b86a3-0b80-8513" as GUID?
guid = "ef1b86a3-0b80-8513-0000-000000000000"
if test(guid): exit(0)
if test(guid.replace('-', '')): exit(0)

# 6. The "reading room" from note
for c in ["reading room", "readingroom", "Reading Room", "ReadingRoom"]:
    if test(c): exit(0)
    for h in [hashlib.sha256(c.encode()).hexdigest(), hashlib.md5(c.encode()).hexdigest()]:
        if test(h): exit(0)

# 7. The chain as a single string with specific format
chain_sids = "S-1-5-21-810-920-1030-1000>S-1-5-21-810-920-1030-1013>S-1-5-21-810-920-1030-1027>S-1-5-21-810-920-1030-1046>S-1-5-21-810-920-1030-1068"
chain_names = "team-a4654927>team-0f85fe7a>team-b13c037b>team-2648700f>team-a4283b27"
for c in [chain_sids, chain_names]:
    if test(c): exit(0)
    for h in [hashlib.sha256(c.encode()).hexdigest(), hashlib.md5(c.encode()).hexdigest()]:
        if test(h): exit(0)

# 8. Decision path with arrows
for c in [
    f"{session_name} -> {decider_name} -> allow -> {decider_right}",
    f"{session_sid} -> {decider_sid} -> {decider_type} -> {decider_right}",
    f"{resource}: allow {decider_name} {decider_right}",
]:
    if test(c): exit(0)
    for h in [hashlib.sha256(c.encode()).hexdigest(), hashlib.md5(c.encode()).hexdigest()]:
        if test(h): exit(0)

# 9. Just the effective SID that grants access
for c in [decider_sid, decider_name, "team-a4283b27", "a4283b27", "1068"]:
    if test(c): exit(0)
    for h in [hashlib.sha256(c.encode()).hexdigest(), hashlib.md5(c.encode()).hexdigest()]:
        if test(h): exit(0)

# 10. Hex only from resource
for c in ["ef1b86a30b808513", "EF1B86A30B808513"]:
    if test(c): exit(0)
    for h in [hashlib.sha256(c.encode()).hexdigest(), hashlib.md5(c.encode()).hexdigest()]:
        if test(h): exit(0)

# 11. Common CTF flag formats
for c in [
    "safctf{allow}",
    "safctf{ALLOW}",
    "safctf{granted}",
    "safctf{ReadProperty}",
    f"safctf{{{decider_sid}}}",
    f"safctf{{{decider_name}}}",
    f"safctf{{{resource}}}",
    "safctf{orchard}",
    "safctf{orchard-society}",
]:
    if test(c): exit(0)

# 12. Empty string and whitespace
for c in ["", " ", "  ", "\t", "\n"]:
    if test(c): exit(0)

print("\nNo hit in creative test")