# Quick Recovery

- **Category:** web
- **Points:** 150
- **Target:** http://54.72.82.22:8010
- **Status:** ✅ SOLVED
- **Flag:** `safctf{69f779b5b18bad69606f1926395e7c2a}`

## Observations

Apache/2.4.68 (Debian), "AFTERHOURS" music-festival theme. Recon found:

- `/robots.txt` — 200, and it leaks a path:

  ```
  User-agent: *
  Disallow: /IKnewYouWouldFindThis/
  # Legacy recovery records use their original file paths.
  ```

- `/IKnewYouWouldFindThis/` — **403**, directory listing disabled (`Options -Indexes`).
- `/login.html` — a decoy: the form is wired to `onsubmit="fakeLogin(event)"`,
  which just calls `alert("Sign-in was unsuccessful...")`. No backend at all.

The robots comment is the whole hint: the records live under that path *using
their original file paths* — i.e. the filenames are the original ones, and a
403 on the directory does not protect the files inside it.

## Exploit

Enumerate filenames inside the 403 directory. The listing is blocked, but the
files themselves are served:

```sh
curl http://54.72.82.22:8010/IKnewYouWouldFindThis/flag.txt
# safctf{69f779b5b18bad69606f1926395e7c2a}

curl http://54.72.82.22:8010/IKnewYouWouldFindThis/flag.php
# safctf{69f779b5b18bad69606f1926395e7c2a}
```

474 candidate names were probed; `flag.txt` and `flag.php` both return 200 with
the flag. Everything else is 404.

## Root cause / fix

Sensitive records are staged in a web-served directory that relies on
`Options -Indexes` for confidentiality. Directory listing is a discoverability
control, not an access control — the files remain directly fetchable. Fix: move
recovery records outside the document root (or behind authentication), so
knowing the filename is not sufficient to read it.

## Reproduction

```sh
.venv/bin/python chal/web/quick-recovery/solve.py
```
