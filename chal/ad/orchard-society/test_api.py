#!/usr/bin/env python3
"""Test API operations with longer timeout."""
import requests

BASE = "http://54.72.82.22:8570"

# Focused API operations that might exist for ad-acl
ops = [
    'decide', 'decision', 'effective', 'effective-access', 'access', 
    'check', 'resolve', 'expand', 'membership', 'groups', 
    'sid', 'resource', 'acl', 'aces', 'ace', 
    'permission', 'rights', 'right', 'allow', 'deny', 
    'grant', 'export', 'dump', 'view', 'read', 'get', 'list', 
    'receipt', 'answer', 'hash', 'flag', 'generate',
    'register', 'exception', 'reading-room', 'readingroom'
]

print("Testing API operations...")
for op in ops:
    try:
        r = requests.get(f'{BASE}/api/{op}', timeout=15)
    except Exception as e:
        print(f"  GET /api/{op}: TIMEOUT/ERROR")
        continue
    if r.status_code == 200 and 'Not found' not in r.text:
        print(f"!!! HIT GET /api/{op}: {r.status_code}")
        print(r.text[:500])
        exit(0)
    elif r.status_code != 404:
        print(f"  GET /api/{op}: {r.status_code} - {r.text[:100]}")

print("\nTesting POST...")
for op in ops:
    for payload in [{}, {'sid': 'S-1-5-21-810-920-1030-1000'}, {'resource': 'record-ef1b86a30b808513'}]:
        try:
            r = requests.post(f'{BASE}/api/{op}', json=payload, timeout=15)
        except Exception:
            continue
        if r.status_code == 200 and 'Not found' not in r.text:
            print(f"!!! HIT POST /api/{op} {payload}: {r.status_code}")
            print(r.text[:500])
            exit(0)
        elif r.status_code != 404:
            print(f"  POST /api/{op} {payload}: {r.status_code} - {r.text[:100]}")

print("\nDone")