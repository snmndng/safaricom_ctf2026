---
title: "Inner Joiner"
ctf: "Safaricom CTF"
date: 2026-10-06
category: web
difficulty: medium
points: 450
flag_format: "safctf{...}"
author: "Strawhats"
---

# Inner Joiner

> **Category:** WEB · **Points:** 450 · **Difficulty:** medium (as designed) / unsolvable (as deployed)

## Summary

Exactly one route exists — `GET /users` — and it is not injectable. It runs a
hardcoded query whose SELECT list names a column (`name`) that does not exist in
the live schema, so it always returns the same MySQL error and never touches any
user input. The challenge is also mislabelled: `TARGETS.md` calls it
Werkzeug/Flask, but the wire is unmistakably **Go `net/http` +
`go-sql-driver/mysql`**. After exhaustive route enumeration and input-channel
fuzzing, there is **no reachable injection surface** — the flag cannot be
exfiltrated as deployed. Same class as Mr Beast Configuration.

## Fingerprint — it's Go, not Flask

The error strings and 404 shape give the stack away:

| Probe | Response | Why it's Go |
| --- | --- | --- |
| `GET /` | `404 page not found` (19 bytes, `text/plain`, `X-Content-Type-Options: nosniff`) | Go's `http.NotFound` |
| malformed request-line | `400 Bad Request`, no `Server:` header | Go `net/http` |
| `GET / HTTP/9.9` | `505 HTTP Version Not Supported: unsupported protocol version` | verbatim Go string |
| `GET /users` | `Error 1054 (42S22): Unknown column 'name' in 'field list'` | verbatim `go-sql-driver/mysql` format |
| `//users` | `301 Moved Permanently` → `/users` | Go `ServeMux` path cleaning |

No `Server:` header on any response — Flask/Werkzeug would emit HTML error pages
and a `Server: Werkzeug/x.y` header. This retargets the whole approach: there is
no Jinja, no Werkzeug debugger, no Python-specific trick to reach for.

## The one route, and why it's dead

```
GET|POST|PUT|PATCH|DELETE|OPTIONS|HEAD /users
  -> 500  Error 1054 (42S22): Unknown column 'name' in 'field list'
```

The query is a `SELECT ... name ... FROM ...` (likely the hinted INNER JOIN
between `users` and a company table) whose field list references a `name` column
that no longer exists — the "retired route" is dead by schema drift. Crucially,
because the unknown column is in the **field list**, MySQL raises error 1054
*before* any `WHERE`/`JOIN` input could matter. So even if the route took input,
the error would mask it.

## Why it is not injectable (exhaustive negatives)

The response is **byte-identical** for every input channel tried:

- **Query params:** all 6,453 burp-parameter-names, all 1–2 letter names, and
  every SQL-ish name (`table`, `join`, `cols`, `select`, `from`, `field`,
  `order`, `filter`, …), each with values `'`, `1`, `*`, `id`, `email`, `users`.
- **Bodies:** form-urlencoded, JSON object, JSON array, raw text, multipart.
- **Cookies** and ~6,453 header names (values `1` / `'`).
- **Path:** `/users/<x>` with ids, usernames and SQLi payloads (`1'`,
  `1'OR'1'='1`), plus matrix/encoded variants (`;`, `%3B`, `%2F`, `%00`,
  `%75sers`).

No parameter, header, cookie or path segment reaches the query.

## Route enumeration (nothing beyond `/users`)

- raft-small (43k), raft-large-words (119.6k), raft-medium-words (63k),
  raft-large-directories (62k), raft-large-files (37k), dirbuster common (30k),
  one/two/three-char and numeric brute force (145k), `path × param` combos (12k),
  compound / camelCase / underscored / dashed / extensioned variants, and
  prefixed forms (`/api/users`, `/v1/users`, `-old`, `legacy_`, `v0|v1|v2`).
- Every non-`/users` path returns Go's `404 page not found`; none returns 301,
  403, 405 or 500.
- Trusted-IP (`X-Forwarded-For: 127.0.0.1`) and routing headers
  (`X-Original-URL`, `X-Rewrite-URL`, `X-Forwarded-Prefix`) make no difference.
- `/robots.txt`, `/.git`, `/.env`, `/debug/pprof`, `/metrics` all 404.
- Method/body sweeps: POST over 119,684 words, PUT/PATCH/DELETE over 189,276,
  a trusted-IP sweep, and a 25-vhost × 10-path Host matrix — the only hit in
  every run is `/users`.

## Verdict

The "retired route" is almost certainly `/users`, and its query is dead on
`Unknown column 'name'`. The hinted "still matters" active route is not
discoverable by enumeration from outside, and the one route that exists accepts
no input. Net effect: **no injection surface is reachable**, so the flag cannot
be exfiltrated as deployed. `solve.py` re-confirms the fingerprint, the single
route, and the byte-identical responses across all input channels.

## Tools

**Used in this solve:**

- Python 3 (`requests`, `concurrent.futures`) for the fingerprint and
  input-channel fuzzing
- ffuf / raft & dirbuster wordlists for route enumeration (raft-small/medium/large)
- raw-socket HTTP probes (malformed request-line, `HTTP/9.9`) to fingerprint the Go stack

**Other tools that fit this task:**

- sqlmap (to confirm non-injectability automatically against `/users`)
- Burp Suite Intruder (parameter/header/cookie matrices)
- gobuster / feroxbuster (alternative content discovery)
- a local Go `net/http` + `go-sql-driver/mysql` repro to study the error path

## Flag

_Not obtained — the only route is a schema-dead, non-injectable query; no reachable injection surface. Broken as deployed._
