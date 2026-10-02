# Inner Joiner (WEB, 450) — http://54.72.82.22:8170

Status: **NO FLAG — blocker** (app inert as deployed; see below).

## TL;DR

Exactly one route exists — `/users` — and it is not injectable. It runs a
hardcoded query whose SELECT list names a column (`name`) that does not exist
in the live schema, so it always returns the same MySQL error and never touches
any user input. No amount of SQLi shaping can change the response.

## Stack (corrected)

The challenge is labelled "Werkzeug/Flask" in `TARGETS.md`, but the wire says
**Go `net/http` + `go-sql-driver/mysql`**:

| Probe | Response | Why it's Go |
| --- | --- | --- |
| `GET /` | `404 page not found` (19 bytes, `text/plain`, `X-Content-Type-Options: nosniff`) | Go's `http.NotFound` |
| malformed request-line | `400 Bad Request` body, no `Server:` header | Go `net/http` |
| `GET / HTTP/9.9` | `505 HTTP Version Not Supported: unsupported protocol version` | verbatim Go string |
| `GET /users` | `Error 1054 (42S22): Unknown column 'name' in 'field list'` | verbatim `go-sql-driver/mysql` error format |
| `//users` | `301 Moved Permanently` → `/users` | Go `ServeMux` path cleaning |

No `Server:` header on any response. Flask/Werkzeug would emit HTML error pages
and a `Server: Werkzeug/x.y` header.

## The one route

```
GET|POST|PUT|PATCH|DELETE|OPTIONS|HEAD /users
  -> 500  Error 1054 (42S22): Unknown column 'name' in 'field list'
```

Query shape inferred: a `SELECT ... name ... FROM ...` (likely the hinted
INNER JOIN between `users` and a company-ish table) whose field list references
a `name` column that no longer exists — i.e. the *retired route* is dead by
schema drift. Because the unknown column is in the **field list**, MySQL raises
it before any WHERE/JOIN clause input could ever matter — so even if the route
took input, the error would mask it.

## Why it is not injectable (exhaustive negatives)

The response is **byte-identical** for every input channel tried:

- query params: all 6453 burp-parameter-names + all 1–2 letter names + every
  SQL-ish name (`table`, `join`, `cols`, `columns`, `select`, `from`, `field`,
  `order`, `sort`, `filter`, …), each with values `'`, `1`, `*`, `id`, `email`,
  `users`; also capitalised names (`Table`, `Query`, …).
- bodies: form-urlencoded, JSON object, JSON array, raw text, multipart.
- cookies and ~6453 header names (values `1` / `'`).
- path: `/users/<x>` with ids, usernames and SQLi payloads (`1'`, `1'OR'1'='1`),
  matrix/encoded variants (`;`, `%3B`, `%3F`, `%2F`, `%00`, `%75sers`).

Conclusion: no parameter, header, cookie or path segment reaches the query.

## Route enumeration (found nothing beyond `/users`)

- raft-small-words (43k), raft-large-words (119.6k), raft-medium-words (63k),
  raft-large-directories (62k), raft-large-files (37k), directory-2.3/common
  (30k), burp-parameter-names (6.4k used as paths), one/two/three-char and
  numeric brute force (145k), `path × param` combinations (12k), compound /
  camelCase / underscored / dashed / extensioned variants, prefixed variants
  (`/api/users`, `/v1/users`, …), all `-old`/`legacy_`/`v0|v1|v2` forms.
- Every non-`/users` path returns Go's `404 page not found`; none returns 301,
  403, 405 or 500.
- Trusted-IP attempts (`X-Forwarded-For: 127.0.0.1` etc.) and header-based
  routing (`X-Original-URL`, `X-Rewrite-URL`, `X-Forwarded-Prefix`) make no
  difference.
- `Server`/`/robots.txt`/`/.git`/`/.env`/`/debug/pprof`/`/metrics` all 404.
- Body/verb sweep (wordlists over four methods), final tallies — the only hit
  in every run is `/users`:
  - POST  over raft-small + raft-medium + dirs + raft-large (119,684) -> `/users` only
  - PUT / PATCH / DELETE over raft-small + raft-medium (189,276)      -> `/users` only
  - X-Forwarded-For trusted-IP sweep                                   -> `/users` only
  - Host-header matrix (25 vhosts x 10 paths)                          -> none

## Blocker

The "retired route" the challenge describes is almost certainly `/users`, and
its query is dead on `Unknown column 'name'`. The hinted "still matters" active
route is **not discoverable** by enumeration from outside and accepts no input
on the route that does exist. Net effect: **no injection surface is reachable**,
so the flag cannot be exfiltrated as deployed.

Same class of finding as `mr-beast-configuration` (broken as deployed).

## Reproduce

```
/home/nomad/safaricom_ctf/.venv/bin/python solve.py
```

`solve.py` re-confirms the fingerprint, the single route, and that no input
channel changes the response.
