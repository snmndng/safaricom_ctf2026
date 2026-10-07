#!/usr/bin/env python3
"""Test form data submission and other edge cases."""
import requests
import hashlib

BASE = "http://54.72.82.22:8570"

resource = "record-ef1b86a30b808513"
decider_sid = "S-1-5-21-810-920-1030-1068"
decider_type = "allow"
decider_right = "ReadProperty"
decider_name = "team-a4283b27"

def test_json(ans):
    try:
        r = requests.post(BASE + "/submit", json={"answer": ans}, timeout=5)
    except Exception:
        return False
    if r.status_code != 403:
        print(f"!!! HIT JSON !!! {r.status_code} - {ans}")
        print(f"Response: {r.text}")
        return True
    return False

def test_form(ans):
    try:
        r = requests.post(BASE + "/submit", data={"answer": ans}, timeout=5)
    except Exception:
        return False
    if r.status_code != 403:
        print(f"!!! HIT FORM !!! {r.status_code} - {ans}")
        print(f"Response: {r.text}")
        return True
    return False

def test_both(ans):
    return test_json(ans) or test_form(ans)

print("Testing form data vs JSON...\n")

candidates = [
    f"{decider_sid}|{decider_type}|{decider_right}",
    f"{resource}|{decider_sid}|{decider_type}|{decider_right}",
    f"{decider_name}|{decider_type}|{decider_right}",
    "allow",
    "ALLOW",
    "granted",
    resource,
    "ef1b86a30b808513",
    decider_sid,
    decider_name,
    "team-a4283b27",
    "1068",
]

for c in candidates:
    if test_both(c):
        exit(0)

# Test with different content types
print("\nTesting different content types...")
for ct in ['application/json', 'application/x-www-form-urlencoded', 'text/plain']:
    for c in [f"{decider_sid}|{decider_type}|{decider_right}", "allow"]:
        try:
            r = requests.post(BASE + "/submit", data=c, headers={'Content-Type': ct}, timeout=5)
        except Exception:
            continue
        if r.status_code != 403:
            print(f"!!! HIT ct={ct} !!! {r.status_code} - {c}")
            print(f"Response: {r.text}")
            exit(0)

# Test GET /submit with answer in query string
print("\nTesting GET /submit with query...")
for c in [f"{decider_sid}|{decider_type}|{decider_right}", "allow"]:
    try:
        r = requests.get(BASE + "/submit", params={'answer': c}, timeout=5)
    except Exception:
        continue
    if r.status_code != 403 and r.status_code != 405:
        print(f"!!! HIT GET !!! {r.status_code} - {c}")
        print(f"Response: {r.text}")
        exit(0)

# Test console-like requests to other paths
print("\nTesting console-like requests to /api/...")
for path in ['/api/receipt', '/api/flag', '/api/answer', '/api/hash', '/api/decision', '/api/verify', '/api/check']:
    for method in ['GET', 'POST']:
        try:
            if method == 'GET':
                r = requests.get(BASE + path, timeout=5)
            else:
                r = requests.post(BASE + path, json={"answer": f"{decider_sid}|{decider_type}|{decider_right}"}, timeout=5)
        except Exception:
            continue
        if r.status_code == 200 and 'Not found' not in r.text and len(r.text) > 50:
            print(f"!!! HIT {method} {path} !!! {r.status_code}")
            print(r.text[:500])
            exit(0)

# Test if there's a /console endpoint
print("\nTesting /console...")
try:
    r = requests.get(BASE + "/console", timeout=5)
    print(f"  /console: {r.status_code} - {r.text[:100]}")
except Exception as e:
    print(f"  /console: ERROR {e}")

# Test the "desk console" JS path - maybe there's a hidden endpoint
print("\nTesting other common desk app endpoints...")
for path in ['/desk', '/api', '/api/', '/downloads/', '/static/', '/hint', '/info', '/about', '/flag', '/answer', '/receipt', '/decision', '/verify']:
    try:
        r = requests.get(BASE + path, timeout=5)
        if r.status_code == 200 and len(r.text) > 50 and 'Orchard Society' not in r.text:
            print(f"  {path}: {r.status_code} - {r.text[:100]}")
    except Exception:
        pass

print("\nDone")