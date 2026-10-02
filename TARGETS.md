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
| 8170 | Inner Joiner | todo | 404 on `/`, Werkzeug |
| 8180 | HEAD Office | solved | |
| 8240 | Tomcat Path Traversal (backend) | dead end | Tomcat 9.0.122, zero webapps; both CVEs N/A (Linux, read-only default) |
| 8300 | Touchline Dispatch | solved | |
| 8310 | Velvet Rehearsal | solved | HTTP param pollution: first `?member=` checked, last signed |
| 8320 | Citrus Proof | todo | Werkzeug |

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
| 8470 | Long Exposure | todo | Werkzeug |

## OSINT
| 8480 | Paper Lanterns | todo | Werkzeug |
| 8490 | Last Tram Home | todo | Werkzeug |
| 8500 | Blue Meridian | todo | Werkzeug |

## REVERSE
| 8510 | Pixel Courier | solved | `/downloads/receipt` is a stripped ELF, not a PNG — checker inversion + XOR |
| 8520 | Clockwork Ballet | solved | stripped ELF: TEA(32 rounds, 0x9e3779b9) + XOR mask at 0x404060 |
| 8530 | Prism Orchestra | solved | 24-byte stack VM: invert XOR/ADD/rol8/swap in reverse + .data XOR |

## AD
| 8570 | Orchard Society | todo | Werkzeug |
| 8580 | Winter Pavilion | todo | Werkzeug |
| 8590 | Crown Studio | todo | Werkzeug |

## UNLISTED (live apps not in CHALLENGES.md)
| 8540 | Pitlane Desk | solved | SUID stage-report -> PATH hijack to root |
| 8550 | Afterparty Crew | solved | sudo tar * wildcard -> --checkpoint-action=exec RCE as root |
| 8560 | Workshop Nocturne | solved | tar symlink member → root job worker copies /root/receipt |
| 8600 | Overtime | solved | 32-bit `40*qty` wrap bypasses `qty>99` (send 2**30) |
| 8610 | Neon Cabaret | solved | `printf(user_buf)` → `%4919c%n` sets win global 0x1337 |
| 8620 | Moonbase Radio | solved | UAF function pointer → ret2win (leak PIE via menu 1) |
| 8630 | Ticket Carousel | solved | BFS the served 40-state DFA: `DAB` reaches closing state 39 |
| 8640 | Double Feature | ? | Werkzeug |
| 8650 | Signal Garden | ? | Werkzeug |

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
| 8130 | No Strings Attached | todo | MOB |
| 8190 | Fragments | solved | keyword-gated /ask: memory|recall|history returns the redacted conversation |
| 8200 | Encore | todo | PWN |
| 8210 | Fancy Details | solved | EXIF Artist ROT13+reverse = AES passphrase; nested tar -> flag.txt |
| 8220 | Fan Signal Lab | solved | Text4Shell CVE-2022-42889 on Commons Text 1.8; GET /home?message= interpolation sink |
| 8230 | Archived | solved | in-band XXE on POST /fetch_user; file:// entity -> dir listing -> /flag8b9d5b8e264a.txt |
| 8330 | Night Bus | todo | API. Desk: `GET /api/orders` lists booking refs, `GET /api/orders/<ref>` returns a receipt — suspect IDOR. (agent died on quota before exploiting) |
| 8340 | Backstage Ledger | todo | API |
| 8350 | Photo Finish | todo | API |
| 8360 | Comeback Pocket | todo | MOB |
| 8370 | Northern Lights | todo | MOB |
| 8380 | Glass Arcade | todo | MOB |
| 8390 | Harbor Lights | todo | CLOUD |
