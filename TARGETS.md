# Safaricom CTF — Live Target Map

All challenges are remote on one host: **`54.72.82.22`**, one port per service.
Discovered 2026-10-02 by port sweep + HTTP fingerprint. Titles come from the page
`<title>`; challenge names from `CHALLENGES*.md`.

Flag format: **`safctf{...}`** (observed: `safctf{` + 32 hex + `}`).

## WEB

| Port | Challenge | Status | Notes |
| --- | --- | --- | --- |
| 8000 | Path Least Travelled | **DOWN** | connection refused (2026-10-02) |
| 8010 | Quick Recovery | solved | |
| 8020 | Templated Malice | solved | |
| 8030 | Sneaky Includes | solved | |
| 8040 | SSTI Secrets | solved | |
| 8050 | Ginger Juice Shop | solved | title "CITRUS STUDIO" — Jinja2 SSTI, blacklist bypass via query args |
| 8060 | Know Your Limits | solved | |
| 8070 | Lightweight Directory | solved | LDAP filter injection (`*)(uid=*))(|(uid=*`) → admin session |
| 8080 | Internal Affairs | solved | |
| 8090 | Secret Vault | solved | login SQLi, WAF spacing bypass (`'OR'`) + leaked AES key |
| 8100 | JWT Forgery | solved | |
| 8110 | Mr Beast Configuration | **blocked** | broken as deployed — see memory |
| 8120 | Prompt Pirate | solved | |
| 8140 | You Snitch | solved | PHP UNION SQLi in `/lookup.php?name=` (PostgreSQL) |
| 8150 | Tomcat Path Traversal (front) | solved | waitress Flask `GET /view?file=` traversal leaks `/app/app.py` creds |
| 8160 | Upload Your Art | solved | |
| 8170 | Inner Joiner | **blocked** | no route — documented dead end. Re-probed 2026-10-02: every path (`/`, `/health`, `/downloads/`, `/submit`, `/api/`, `/robots.txt`) returns the bare `404 page not found`, i.e. Go's `http.NotFound`, not a Werkzeug HTML 404. The listener is up but registers no handlers. |
| 8180 | HEAD Office | solved | |
| 8240 | Tomcat Path Traversal (backend) | dead end | Tomcat 9.0.122, zero webapps; both CVEs N/A (Linux, read-only default) |
| 8300 | Touchline Dispatch | solved | |
| 8310 | Velvet Rehearsal | solved | HTTP param pollution: first `?member=` checked, last signed |
| 8320 | Citrus Proof | solved | see chal/ NOTES.md |

## CLOUD
| 8400 | Stageworks | solved | fake-AWS AssumeRole chain: leaked externalId + session tag |
| 8410 | Greenroom Atlas | solved | fake-K8s RBAC: automount SA token via workload logs → `/api/secrets` |

## CRYPTO
| 8420 | Three Encores | solved | RSA e=3, identical ciphertexts → plain integer cube root |
| 8430 | Parallel Lines | solved | keystream reuse across the two parallel exports |
| 8440 | Midnight Parcel | solved | CBC padding oracle on POST /api/receipt |

## FORENSICS
| 8450 | Matchday Replay | solved | raw USER0 records, out-of-order reassembly + period-12 keystream |
| 8460 | Second Pressing | solved | SQLite WAL — recover the pre-revision frame |
| 8470 | Long Exposure | **blocked** | 350-pt FOR. Verdict after round 2: most likely **broken as deployed** (dropped seed/recipe file) — same class as 8110/8350. The sibling matchday-replay periodic-XOR rule is *proven* not to apply (no valid keystream period in 7..66 across all 8! fragment perms); no seed/card id is reachable in any shipped file or via any sibling. Do not re-attempt without the organizer generator. See `chal/forensics/long-exposure/NOTES.md`. |

## OSINT
| 8480 | Paper Lanterns | solved | see chal/ NOTES.md |
| 8490 | Last Tram Home | solved | see chal/ NOTES.md |
| 8500 | Blue Meridian | solved | see chal/ NOTES.md |

## REVERSE
| 8510 | Pixel Courier | solved | `/downloads/receipt` is a stripped ELF, not a PNG — checker inversion + XOR |
| 8520 | Clockwork Ballet | solved | stripped ELF: TEA(32 rounds, 0x9e3779b9) + XOR mask at 0x404060 |
| 8530 | Prism Orchestra | solved | 24-byte stack VM: invert XOR/ADD/rol8/swap in reverse + .data XOR |

## AD
| 8570 | Orchard Society | todo | Werkzeug |
| 8580 | Winter Pavilion | solved | see chal/ NOTES.md |
| 8590 | Crown Studio | solved | see chal/ NOTES.md |

## UNLISTED (live apps not in CHALLENGES.md)
| 8540 | Pitlane Desk | solved | SUID stage-report -> PATH hijack to root |
| 8550 | Afterparty Crew | solved | sudo tar * wildcard -> --checkpoint-action=exec RCE as root |
| 8560 | Workshop Nocturne | solved | tar symlink member → root job worker copies /root/receipt |
| 8600 | Overtime | solved | 32-bit `40*qty` wrap bypasses `qty>99` (send 2**30) |
| 8610 | Neon Cabaret | solved | `printf(user_buf)` → `%4919c%n` sets win global 0x1337 |
| 8620 | Moonbase Radio | solved | UAF function pointer → ret2win (leak PIE via menu 1) |
| 8630 | Ticket Carousel | solved | BFS the served 40-state DFA: `DAB` reaches closing state 39 |
| 8640 | Double Feature | solved | duplicate zip members: read(ZipInfo) vs read(name) |
| 8650 | Signal Garden | solved | two-tone FSK: AA55 sync + 71 frames of [alternating marker][7 data bits] -> complement odd frames -> Base32 -> flag |

## "Offline" set — actually live behind desk apps (found 2026-10-02)

The challenges with no obvious port each have a **desk page** on the host whose
"Remote desk / Remote channel" line gives the real endpoint. Found by reading the
page text of the unlisted ports:

| Desk app | Port | Desk page | Remote endpoint | Artifact |
| --- | --- | --- | --- | --- |
| Pitlane Desk | 8540 | `:8540/` | `ssh player@54.72.82.22 -p 8700` (pw `matinee-visitor`) | — |
| Afterparty Crew | 8550 | `:8550/` | `ssh player@54.72.82.22 -p 8710` (pw `matinee-visitor`) | — |
| Workshop Nocturne | 8560 | `:8560/` | `ssh player@54.72.82.22 -p 8720` (pw `matinee-visitor`) | `/downloads/sample-job.tar` |
| Overtime | 8600 | `:8600/` | `nc 54.72.82.22 8730` | `/downloads/receipt` |
| Neon Cabaret | 8610 | `:8610/` | `nc 54.72.82.22 8740` | `/downloads/receipt` |
| Moonbase Radio | 8620 | `:8620/` | `nc 54.72.82.22 8750` | `/downloads/receipt` |
| Ticket Carousel | 8630 | `:8630/` | HTTP API on the desk itself | `/downloads/carousel.map` |

Live banners (python socket; this box has **no `nc` binary**):
- 8700/8710/8720 → `SSH-2.0-OpenSSH_10.0p2 Debian-7+deb13u4`
- 8730 → `Overtime tickets. Quantity?\n`
- 8740 → `Neon Cabaret. Guest line:\n`
- 8750 → `Moonbase Radio\n`

Ticket Carousel (8630) advertises `POST /api/round` (starts a round) and
`POST /api/move` (accepts `round`, `symbol`).

## Offline / not found
- 8000 — Path Least Travelled: **DOWN** (connection refused, rechecked 2026-10-02)
- AI/ML, XXE (`Archived`), API (`Night Bus`), PWN (`Encore`), CVE (`Text4Shell Lab`),
  MOB (`No Strings Attached`, `Comeback Pocket`, `Northern Lights`, `Glass Arcade`),
  FOR (`Fancy Details`) — no port identified yet; may live on another host or need
  artifacts from the platform. The desk apps above are the best candidates for these.

## Gotcha: `/submit` 403 is not the WAF

Every desk app answers a **wrong** `/submit` with
`403 {"message":"The request could not be completed.","ok":false}` — visually
identical to the shared WAF's rejection. A **correct** answer returns
`200 {"message":"<the real flag>","ok":true}`. So a 403 from `/submit` means
"not the answer yet", not "blocked". (Confirmed on 8450 and 8630.)

## Newly-mapped ports (from the platform's remaining list, 2026-10-02)

Ports we had never found. Same host, same `safctf{}` flag.

| Port | Challenge | Status | Notes |
| --- | --- | --- | --- |
| 8130 | No Strings Attached | solved | see chal/ NOTES.md |
| 8190 | Fragments | solved | keyword-gated /ask: memory|recall|history returns the redacted conversation |
| 8200 | Encore | solved | 3-stage: XOR + Vigenere/ROT13 + gets() ret2win; answers to /submit/stageN |
| 8210 | Fancy Details | solved | EXIF Artist ROT13+reverse = AES passphrase; nested tar -> flag.txt |
| 8220 | Fan Signal Lab | solved | Text4Shell CVE-2022-42889 on Commons Text 1.8; GET /home?message= interpolation sink |
| 8230 | Archived | solved | in-band XXE on POST /fetch_user; file:// entity -> dir listing -> /flag8b9d5b8e264a.txt |
| 8330 | Night Bus | solved | BOLA: object = sha256(reference)[:24]; next_reference leaks TOUR-2402 receipt |
| 8340 | Backstage Ledger | solved | see chal/ NOTES.md |
| 8350 | Photo Finish | **blocked** | re-fingerprinted 2026-10-02: stock **unregistered Nessus Expert** UI (HTTPS-only, `Server: NessusWWW`). Challenge app not deployed — see below. |
| 8360 | Comeback Pocket | solved | see chal/ NOTES.md |
| 8370 | Northern Lights | solved | see chal/ NOTES.md |
| 8380 | Glass Arcade | solved | see chal/ NOTES.md |
| 8390 | Harbor Lights | solved | see chal/ NOTES.md |

## `/submit` availability across the remaining ports (probed 2026-10-02)

`GET /submit` → **405** (POST-only route exists) means the app is a **desk app**:
recover the receipt, then `POST /submit {"answer": "<receipt>"}` — that returns the
**graded** flag. The recovered value is frequently only an intermediate.

| Port | Challenge | `GET /submit` | `POST /submit` | Read |
| --- | --- | --- | --- | --- |
| 8320 | Citrus Proof | 405 | 403 | desk app — submit the receipt |
| 8340 | Backstage Ledger | 405 | 403 | desk app |
| 8480 | Paper Lanterns | 405 | 403 | desk app |
| 8490 | Last Tram Home | 405 | 403 | desk app |
| 8500 | Blue Meridian | 405 | 403 | desk app |
| 8570 | Orchard Society | 405 | 403 | desk app |
| 8580 | Winter Pavilion | 405 | 403 | desk app |
| 8590 | Crown Studio | 405 | 403 | desk app |
| 8640 | Double Feature | 405 | 403 | desk app |
| 8650 | Signal Garden | 405 | 403 | desk app |
| 8360 | Comeback Pocket | 405 | 403 | desk app |
| 8370 | Northern Lights | 405 | 403 | desk app |
| 8380 | Glass Arcade | 405 | 403 | desk app |
| 8390 | Harbor Lights | 405 | 403 | desk app |
| 8470 | Long Exposure | 405 | 403 | desk app |
| 8170 | Inner Joiner | 404 | 404 | no route — documented dead end |
| 8130 | No Strings Attached | 404 | 404 | Apache 2.4.68, serves a file (MOB) |
| 8350 | Photo Finish | 400 | 400 | answers as `NessusWWW` — see below |

## Photo Finish (8350) — likely a host-side deployment fault

Re-fingerprinted 2026-10-02 and exhausted: Host-header vhosts (challenge name,
neighbours, `localhost`, the IP), TLS SNI routing, ~130 direct app paths, a
**full 1–65535 TCP sweep** (only the known ports plus a data-less transient
`:2000`), HTTP/2, `/downloads`, ~55 Nessus endpoints, and the unauthenticated
Nessus setup/cred paths. The port serves a **stock, unregistered Nessus Expert**
web UI, and it is the lone outlier in a block where every neighbouring port
answers as Werkzeug/Flask.

No credentials or artifacts are obtainable by recon. Conclusion: the challenge
app is **not deployed on this port** — a host-side fault, not a solvable service.
Recorded rather than re-attempted, same treatment as Mr Beast (8110).

Artifacts: `chal/api/photo-finish/NOTES.md` + `solve.py` (a re-fingerprinting
harness that also drives the standard desk-app `/submit` flow should a real
Werkzeug API ever appear on this port).

## Lead closed: desk apps advertise 8700–8750

The Photo Finish agent observed that the six desk apps point at **SSH/nc ports
in the 8700–8750** range. Re-verified 2026-10-02 with a direct connect sweep of
8700–8759: the listeners are all already-solved challenges, not a new target.

| Port | Banner | Owner |
| --- | --- | --- |
| 8700 | SSH-2.0-OpenSSH_10.0p2 | Pitlane Desk :8540 (solved) |
| 8710 | SSH-2.0-OpenSSH_10.0p2 | Afterparty Crew :8550 (solved) |
| 8720 | SSH-2.0-OpenSSH_10.0p2 | Workshop Nocturne :8560 (solved) |
| 8730/8740/8750 | pwn service banners | Overtime/Neon Cabaret/Moonbase Radio (solved) |

Nothing else in 8700–8759 is listening. Lead closed.
