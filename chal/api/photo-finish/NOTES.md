# Photo Finish — API, 750 pts (board lists 400)

Target: `http://54.72.82.22:8350` — **the challenge app is not deployed on this
port**. The port serves a stock, unregistered **Nessus Expert** web UI.

**Result: no flag. The challenge is unreachable as deployed.** (Same class of
breakage as `web/mr-beast-configuration`.)

## Fingerprint of :8350 (re-verified from scratch)

```
GET http://54.72.82.22:8350/   -> 400, Server: NessusWWW
    body: "You're speaking plain HTTP to an SSL-enabled server port..."
GET https://54.72.82.22:8350/  -> 200, Server: NessusWWW, <title>Nessus</title>
```

The port is **HTTPS-only and is Nessus**. Compare with the normal banner shape of
the neighbouring challenge ports (all identical Werkzeug/Flask apps):

```
GET http://54.72.82.22:8340/   -> 200, Server: Werkzeug/3.1.9 Python/3.11.16
```

Port 8350 is the **only** outlier in the whole 8xxx block — every other API/web
port answers as Werkzeug (or Apache/nginx/Express/raw-TCP for the others).

## What the port actually is

`https://54.72.82.22:8350/server/status` (unauthenticated) returns a genuine
Nessus status document:

```json
{"code":503,
 "detailed_status":{"login_status":"allow","feed_status":{"status":"downloading-failed"},
                    "db_status":{"status":"ready"},"engine_status":{"status":"ready"}},
 "pluginSet":true,"pluginData":true,"initLevel":4,"status":"download-failed"}
```

`/server/properties` -> `{"nessus_type":"Nessus Expert","paid":false, ...}`.
`/api` serves the real "Nessus API Documentation" page. This is a real Nessus
install (unregistered / feed download failed), not a challenge service wearing a
Nessus banner.

## Hypotheses tested (all negative)

| Hypothesis | Test | Result |
| --- | --- | --- |
| App is virtual-hosted | `Host:` = `photo-finish`, `photofinish`, `photo.finish`, `api`, `localhost`, `finish`, `photo`, the IP, `chal-api-photo-finish` | Nessus answers identically for every Host (200 `NessusWWW`) |
| App is SNI-routed | TLS SNI set to the same names | Nessus cert/handler every time |
| App is path-routed | `/api`, `/api/orders`, `/api/photos`, `/api/frames`, `/submit`, `/health`, `/docs`, `/openapi.json`, `/robots.txt`, `/orders`, `/photos`, `/frames`, … (~130 paths fuzzed) | All Nessus 404 JSON, or Nessus's own `/api`, `/server/status`, `/scans`, `/policies`, `/folders`, `/session`, `/users` routes |
| App is on a neighbouring port | full TCP sweep 1–65535 | only the known 8xxx challenge ports (+ a transient, data-less `:2000`) |
| App reached via HTTP/2 | `--http2`, `--http2-prior-knowledge` | stacks on the same Nessus TLS handler; h2c refused |
| App deliverable is a `/downloads/*` artifact | enumerated `/downloads/` links on all 47 live apps | none photo-related; no Photo Finish artifact anywhere |
| Flag leaks from Nessus unauth | swept ~55 Nessus endpoints for `safctf` | nothing; all data routes are 401/403/405 |
| Nessus default creds / setup | (inherited) prior agent tried ~50 base words × suffixes × 5 users on `POST /session`, plus `POST /server/unlock`, SQLi in `username`/`password`, JSON type-confusion (`bool`/`null`/`list`/`dict`), method fuzzing | all `401 Invalid Credentials`; `POST /users` resets the connection (route disabled); no default creds |

There is **no** desk page for Photo Finish: every "desk" port (8540–8650) was
fetched and grepped for `Remote …: <endpoint>` lines — the six that exist point
at the SSH/nc ports 8700–8750, none reference `8350` or Photo Finish.

## Why I stopped

- No credential or artifact for the challenge is obtainable by recon (nothing on
  the port, nothing in any desk page, no `/downloads` artifact).
- The only live service on the mapped port is a third-party scanner product with
  no unauthenticated data leak; attacking Nessus itself is off-brief and has no
  route in.
- Conclusion: the Photo Finish container is not deployed (or is behind a broken
  port mapping). This is a deployment fault on the CTF host, not a solvable
  service. Reported so the board can be corrected.

## Board-level evidence

`TARGETS.md` (commit `c723c13`, "record /submit availability across remaining
ports") already records this port as the lone anomaly:

```
| 8350 | Photo Finish | GET /submit 400 | POST /submit 400 | answers as NessusWWW — needs re-fingerprinting |
```

15 of the 18 remaining ports showed `GET /submit -> 405` (the desk-app signature).
8350 showed **400 for both GET and POST** `/submit` — i.e. it never even reached
a Flask router. Nothing about the port matches the challenge pattern.

## solve.py

`solve.py` re-runs the whole fingerprint automatically: banner shape (HTTP vs
HTTPS), Host/SNI vhost routing, direct app-path probing, and — should a real
Werkzeug JSON API ever appear on the port — it drives the board's standard desk
flow (`POST /submit {"answer": "<receipt>"}` -> `200 {"ok":true,"message":"safctf{...}"}`).
Today it prints the "Nessus, app not deployed" verdict and exits non-zero.

If the platform ever redeploys the real app on 8350, re-running `solve.py` will
immediately tell you whether it is a Werkzeug app and whether `/submit` exists;
the intended exploit (given this board's API pattern — see `chal/api/night-bus`)
is almost certainly a BOLA/IDOR on a `/api/…/<id>` endpoint with a derivable id.

---

# ROUND 3 — 2026-10-02 (branch `chal/api-photo-finish-r3`)

**Result: still no flag. The "app lives on another port" hypothesis is falsified
by a full host sweep.** :8350 is unchanged stock Nessus.

## 1. Re-fingerprint of :8350 (byte-exact, today)

```
GET http://54.72.82.22:8350/   -> 400, Server: NessusWWW
    "You're speaking plain HTTP to an SSL-enabled server port."
GET https://54.72.82.22:8350/  -> 200, Server: NessusWWW, <title>Nessus</title>
    TLSv1.3 TLS_AES_256_GCM_SHA384, HSTS, CSP form-action 'self' … tenable.com
    cert has no CN/SAN (self-signed internal)
```

Over TLS, the whole surface is Nessus, not a Flask app:

| Probe (https) | Result |
| --- | --- |
| `/` | 200 — Nessus UI (`<title>Nessus</title>`) |
| `/api` | 200 — page titled **"Nessus API Documentation"** (`nessus6-api.css`) |
| `/submit` | **404 `File not found`** — Nessus's own JSON 404, *not* Flask |
| `/api/orders`, `/api/photos`, `/api/races`, `/api/finish`, `/downloads/` | 404 `{"error":"The requested file was not found."}` |
| `/server/properties` | 200 `{"nessus_type":"Nessus Expert","paid":false,…}` |

Host-header **and** TLS-SNI routing re-tested with `photo-finish`, `photofinish`,
`photo.finish`, `api`, `localhost`, `finish`, `photo`, `8350`,
`chal-api-photo-finish`, the bare IP — **every one returns the Nessus page**. No
vhost, no SNI routing.

## 2. Host sweep 8000–8800 (the new lead) — no Photo Finish desk exists

Swept every HTTP port 8000–8800 (thread pool) and grepped each page's
`<title>`/`<h1>`/body for `photo|finish|moment|final second|freez|shutter|exposure`.

- **59–65 live HTTP services**, all on the 80xx/81xx/82xx (scenario style) or
  83xx–86xx (desk style) bands. **None** is titled "Photo Finish" or names this
  challenge. Keyword hits are only incidental, and each is a *different*,
  already-solved challenge:
  - `8030` SIDE QUEST ("a brief **moment** of calm") — Sneaky Includes
  - `8210` FRAME / FOUND ("travel **photography**", `/downloads/photo.jpg`) — Fancy Details
  - `8470` Long Exposure ("some **moments** belong to the blue hour") — Long Exposure
- **Desk-app signature** (`GET /submit -> 405`, `POST /submit {"answer":"x"} -> 403`)
  is present on **every** 83xx–86xx challenge port **except 8350**:
  `[8300,8310,8320,8330,8340, 8360,8370,8380,8390,8400,8410,8420,8430,8440,
    8450,8460,8470,8480,8490,8500,8510,8520,8530,8540,8550,8560,8570,8580,8590,
    8600,8610,8620,8630,8640,8650]`.
  Photo Finish's slot is `8350`, and `8350/submit` is Nessus `400/404`. The desk
  band is contiguous around it; the one missing member is exactly this challenge.
- **Full-range connect scan** of 1–8000 and 8801–65535 found exactly **one**
  other open port, `5060`, which speaks no HTTP and closes on HTTP/1.1 (no
  banner on empty/SIP/TLS probes) — a dead/filtered socket, not a web app.

Only one host is ever referenced anywhere in the repo (`54.72.82.22`); there is
no second IP.

## 3. Verdict

Every port on `54.72.82.22` is accounted for: all 59–65 live HTTP services are
known, solved challenges; the lone unlisted open port (`5060`) serves nothing;
and `8350` — Photo Finish's assigned port — is a stock unregistered Nessus
Expert install with no challenge route, no `/submit`, and no obtainable
credential or artifact. **The Photo Finish app is genuinely not deployed on this
host.** This is a host-side deployment fault (a foreign Nessus process squatting
the challenge's port), not a solvable service — same class as `8110`
Mr Beast Configuration. `solve.py --sweep` re-runs this verification end-to-end.
