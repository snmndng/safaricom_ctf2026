---
title: "Photo Finish"
ctf: "Safaricom CTF"
date: 2026-10-06
category: web
difficulty: hard
points: 400
flag_format: "safctf{...}"
author: "Strawhats"
---

# Photo Finish

> **Category:** API · **Points:** 400 (board) / 750 (bundle) · **Difficulty:** hard

## Summary

Photo Finish's assigned port, `8350`, does **not** serve the challenge
application. It serves a stock, unregistered **Nessus Expert** web UI
(HTTPS-only, `Server: NessusWWW`). Every other API/web port in the `8xxx` block
answers as the same Werkzeug/Flask desk app; `8350` is the lone outlier. After a
full-host port sweep and exhaustive vhost/SNI/path routing tests, the conclusion
is that **the Photo Finish container is not deployed** — a foreign Nessus
process is squatting the port. No flag is obtainable by recon. This is a
host-side deployment fault, the same class as Mr Beast Configuration (`:8110`).

This writeup documents the investigation that establishes that verdict, because
"prove the target is broken, and prove it rigorously" is itself the deliverable
here.

## Recon — fingerprinting the port

The first probe already looked wrong. Every sibling port answers plain HTTP with
a Werkzeug banner; `8350` rejects plain HTTP and demands TLS:

```
GET  http://54.72.82.22:8350/   -> 400, Server: NessusWWW
     body: "You're speaking plain HTTP to an SSL-enabled server port."
GET  https://54.72.82.22:8350/  -> 200, Server: NessusWWW, <title>Nessus</title>
```

Compare the normal shape of a neighbouring challenge port:

```
GET  http://54.72.82.22:8340/   -> 200, Server: Werkzeug/3.1.9 Python/3.11.16
```

Reading the port over TLS, the entire surface is Nessus, not Flask:

| Probe (https) | Result |
| --- | --- |
| `/` | 200 — Nessus UI (`<title>Nessus</title>`) |
| `/api` | 200 — page titled **"Nessus API Documentation"** |
| `/server/status` | 200 — genuine Nessus status JSON (`"status":"download-failed"`) |
| `/server/properties` | 200 — `{"nessus_type":"Nessus Expert","paid":false,...}` |
| `/submit` | **404 `File not found`** — Nessus's own JSON 404, *not* Flask |
| `/api/orders`, `/api/photos`, `/downloads/` | 404 `{"error":"The requested file was not found."}` |

`/server/status` returning a real Tenable status document (feed download failed,
engine ready, unregistered) is conclusive: this is a real Nessus install, not a
challenge service wearing a Nessus banner.

## Hypotheses tested — and falsified

Because a port *could* multiplex the real app behind a vhost, SNI, or path, each
routing possibility was tested and ruled out:

| Hypothesis | Test | Result |
| --- | --- | --- |
| Virtual-hosted app | `Host:` = `photo-finish`, `photofinish`, `api`, `localhost`, the IP, `chal-api-photo-finish`, … | Nessus answers identically for every Host |
| SNI-routed app | TLS SNI set to the same names | Nessus cert/handler every time |
| Path-routed app | ~130 paths (`/api/orders`, `/submit`, `/health`, `/docs`, `/openapi.json`, …) | all Nessus 404 JSON, or Nessus's own routes |
| App on a neighbour port | full TCP sweep 1–65535 | only the known `8xxx` challenge ports (+ a dead `:5060`) |
| HTTP/2 smuggle | `--http2`, `--http2-prior-knowledge` | stacks on the same Nessus TLS handler; h2c refused |
| Deliverable is a `/downloads/*` artifact | enumerated `/downloads/` on all ~47 live apps | no Photo Finish artifact anywhere |
| Flag leaks from Nessus unauth | swept ~55 Nessus endpoints for `safctf` | nothing; all data routes 401/403/405 |
| Nessus default creds | ~50 base words × suffixes × 5 users on `POST /session`, SQLi, JSON type-confusion, method fuzzing | all `401 Invalid Credentials`; no default creds |

## The decisive sweep

The strongest hypothesis — "the app lives on another port" — was killed by
sweeping every HTTP port `8000–8800` and grepping each page's title/body for the
challenge's keywords (`photo|finish|moment|final second|freez|shutter|exposure`):

- **59–65 live HTTP services**, all already-identified challenges. Keyword hits
  were incidental and each belonged to a *different*, solved challenge (`8030`
  Sneaky Includes "a brief **moment** of calm"; `8210` Fancy Details "travel
  **photography**"; `8470` Long Exposure "some **moments** belong to the blue
  hour").
- The **desk-app signature** (`GET /submit -> 405`, `POST /submit -> 403`) is
  present on **every** `83xx–86xx` port **except 8350**. The desk band is
  contiguous around it; the one missing member is exactly this challenge.
- A full connect scan of `1–8000` and `8801–65535` found exactly one other open
  port, `5060`, which speaks no HTTP and closes on any probe — a dead socket.

Only one host (`54.72.82.22`) is ever referenced in the entire challenge set, so
there is no second IP to pivot to.

## Verdict

Every port on the host is accounted for: all live HTTP services are known,
solved challenges; the lone unlisted open port serves nothing; and `8350` —
Photo Finish's assigned slot — is a stock unregistered Nessus Expert with no
challenge route, no `/submit`, and no obtainable credential or artifact. **The
Photo Finish app is genuinely not deployed.** Reported so the board can be
corrected.

`solve.py --sweep` re-runs this verification end-to-end. If the platform ever
redeploys the real app on `8350`, re-running it will immediately report whether a
Werkzeug app with `/submit` has appeared; given this board's API pattern (see
`chal/api/night-bus`), the intended bug is almost certainly a BOLA/IDOR on an
`/api/.../<id>` endpoint with a derivable identifier.

## Tools

**Used in this solve:**

- Python 3 (recon harness: `requests`, `socket`, `ssl`, `concurrent.futures`)
- openssl / raw TLS probing (plain-HTTP-vs-TLS banner split, SNI tests)
- a full-range TCP port sweep (threaded connect scan)

**Other tools that fit this task:**

- nmap (`-sV --version-all`, `ssl-cert`, `http-title` NSE scripts) for service ID
- Burp Suite / ffuf for vhost and path routing tests at scale
- `testssl.sh` / `sslscan` to confirm the TLS stack and certificate
- Nessus API client tooling, had a credential ever surfaced

## Flag

_Not obtained — the challenge service is not deployed on its assigned port (stock Nessus squats `:8350`)._
