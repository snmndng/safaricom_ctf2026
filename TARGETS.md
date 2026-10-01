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
| 8310 | Velvet Rehearsal | todo | Werkzeug |
| 8320 | Citrus Proof | todo | Werkzeug |

## CLOUD
| 8400 | Stageworks | solved | fake-AWS AssumeRole chain: leaked externalId + session tag |
| 8410 | Greenroom Atlas | todo | Werkzeug |

## CRYPTO
| 8420 | Three Encores | solved | RSA e=3, identical ciphertexts → plain integer cube root |
| 8430 | Parallel Lines | solved | keystream reuse across the two parallel exports |
| 8440 | Midnight Parcel | todo | Werkzeug |

## FORENSICS
| 8450 | Matchday Replay | todo | Werkzeug |
| 8460 | Second Pressing | todo | Werkzeug |
| 8470 | Long Exposure | todo | Werkzeug |

## OSINT
| 8480 | Paper Lanterns | todo | Werkzeug |
| 8490 | Last Tram Home | todo | Werkzeug |
| 8500 | Blue Meridian | todo | Werkzeug |

## REVERSE
| 8510 | Pixel Courier | solved | `/downloads/receipt` is a stripped ELF, not a PNG — checker inversion + XOR |
| 8520 | Clockwork Ballet | todo | Werkzeug |
| 8530 | Prism Orchestra | todo | Werkzeug |

## AD
| 8570 | Orchard Society | todo | Werkzeug |
| 8580 | Winter Pavilion | todo | Werkzeug |
| 8590 | Crown Studio | todo | Werkzeug |

## UNLISTED (live apps not in CHALLENGES.md)
| 8540 | Pitlane Desk | ? | Werkzeug |
| 8550 | Afterparty Crew | ? | Werkzeug |
| 8560 | Workshop Nocturne | ? | Werkzeug |
| 8600 | Overtime | ? | Werkzeug |
| 8610 | Neon Cabaret | ? | Werkzeug |
| 8620 | Moonbase Radio | ? | Werkzeug |
| 8630 | Ticket Carousel | ? | Werkzeug |
| 8640 | Double Feature | ? | Werkzeug |
| 8650 | Signal Garden | ? | Werkzeug |

## Offline / not found
- 8700 — refused
- AI/ML, XXE (`Archived`), API (`Night Bus`), PWN (`Encore`), CVE (`Text4Shell Lab`),
  MOB (`No Strings Attached`, `Comeback Pocket`, `Northern Lights`, `Glass Arcade`),
  FOR `Fancy Details` — no port identified yet; may live on another host or need
  artifacts from the platform.
