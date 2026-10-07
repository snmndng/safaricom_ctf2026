# Safaricom CTF 2026 — Strawhats writeups

Detailed discovery→exploit writeups for **61 challenges**. **57 solved / 4 documented-but-unsolved** (22620 of 23920 pts captured).

Each writeup carries the full hunt from our working notes — recon, fingerprinting, the bug, dead ends, the exploit script — plus a **Tools** section (what we used, and what else fits the category). The three unsolved entries are documented as broken-as-deployed investigations.

## Index

| Category | Challenge | Pts | Status | Flag | Writeup |
| --- | --- | --- | --- | --- | --- |
| ad | Crown Studio | 750 | ✅ solved | `safctf{04fd9ff98e41c5ef8a54da3990126b58}` | [md](writeup-ad-crown-studio.md) |
| ad | Winter Pavilion | 500 | ✅ solved | `safctf{8a97f3881e4828d37406ed0953ff9573}` | [md](writeup-ad-winter-pavilion.md) |
| ad | Orchard Society | 300 | ⚠️ no flag | — | [md](writeup-ad-orchard-society.md) |
| ai-ml | Fragments | 300 | ✅ solved | `safctf{d432e09718e6cb46387f54e27dbc0168}` | [md](writeup-ai-fragments.md) |
| cloud | Greenroom Atlas | 750 | ✅ solved | `safctf{6035ffad158ce604cb84927b77926d47}` | [md](writeup-cloud-greenroom-atlas.md) |
| cloud | Stageworks | 500 | ✅ solved | `safctf{b9d2678027feea5870c41931b663fd6d}` | [md](writeup-cloud-stageworks.md) |
| cloud | Harbor Lights | 300 | ✅ solved | `safctf{0a7fe9c5e49d7fbe62cea634195d0adf}` | [md](writeup-cloud-harbor-lights.md) |
| crypto | Midnight Parcel | 750 | ✅ solved | `safctf{8a99e6bb-7903-4f4e-b42a-7e594982528b}` | [md](writeup-crypto-midnight-parcel.md) |
| crypto | Parallel Lines | 500 | ✅ solved | `safctf{0983d7d0-b930-468f-ac25-ecc6feecc856}` | [md](writeup-crypto-parallel-lines.md) |
| crypto | Three Encores | 300 | ✅ solved | `safctf{0471ad15e84bb9f630e394e49dde85a9}` | [md](writeup-crypto-three-encores.md) |
| forensics | Second Pressing | 500 | ✅ solved | `safctf{12bbc51d-7450-44c6-af3f-1723514b8aad}` | [md](writeup-forensics-second-pressing.md) |
| forensics | Long Exposure | 350 | ✅ solved | `safctf{f4946c9564b982892e9d41315b3ec739}` | [md](writeup-forensics-long-exposure.md) |
| forensics | Fancy Details | 300 | ✅ solved | `safctf{245ccf0110f6422d41671064cee8da68}` | [md](writeup-forensics-fancy-details.md) |
| forensics | Matchday Replay | 300 | ✅ solved | `safctf{5554fd00-017a-4915-a883-a7ef2639f73b}` | [md](writeup-forensics-matchday-replay.md) |
| malware | Glass Arcade | 750 | ✅ solved | `safctf{318223415bd0e96e2f63b0dd88eacf2d}` | [md](writeup-mobile-glass-arcade.md) |
| malware | Northern Lights | 500 | ✅ solved | `safctf{3fd96340be891c629f7e3f3a42202743}` | [md](writeup-mobile-northern-lights.md) |
| malware | Comeback Pocket | 300 | ✅ solved | `safctf{408e83b586354238e5a8e968a74b8b64}` | [md](writeup-mobile-comeback-pocket.md) |
| malware | No Strings Attached | 300 | ✅ solved | `safctf{94f40cc66658c67503a859cf383c7622}` | [md](writeup-mobile-no-strings-attached.md) |
| malware | Secure Vault | 300 | ✅ solved | `safctf{d9d4c9e7-0f00-48dd-937d-0337bfb14baa}` | [md](writeup-mobile-secure-vault.md) |
| malware | Fan Signal Lab | 150 | ✅ solved | `safctf{e5ca75a4e6e0507f9dd29be81997b9b6}` | [md](writeup-cve-fan-signal-lab.md) |
| misc | Workshop Nocturne | 500 | ✅ solved | `safctf{1cf16fdf78edcd426f2b8e008c329206}` | [md](writeup-misc-workshop-nocturne.md) |
| misc | Afterparty Crew | 300 | ✅ solved | `safctf{66bda7b8ede495eb131f6bf5bbb9d889}` | [md](writeup-misc-afterparty-crew.md) |
| misc | Double Feature | 300 | ✅ solved | `safctf{513195eb399c59321e043c54773185b7}` | [md](writeup-misc-double-feature.md) |
| misc | Pitlane Desk | 300 | ✅ solved | `safctf{9cca688790c893101757448298adfb67}` | [md](writeup-misc-pitlane-desk.md) |
| misc | Signal Garden | 300 | ✅ solved | `safctf{4e9f5e83-5c32-4444-864e-7aec3fd8ecc6}` | [md](writeup-misc-signal-garden.md) |
| misc | Ticket Carousel | 300 | ✅ solved | `safctf{5b701cd93c298559638b8b4181bfa5e2}` | [md](writeup-misc-ticket-carousel.md) |
| osint | Blue Meridian | 750 | ✅ solved | `safctf{756f7d81426571a6d6dac9b1aae5f271}` | [md](writeup-osint-blue-meridian.md) |
| osint | Last Tram Home | 500 | ✅ solved | `safctf{a7290ed4a3ba7af7bd4b4c529eb99314}` | [md](writeup-osint-last-tram-home.md) |
| osint | Paper Lanterns | 300 | ✅ solved | `safctf{38309964a77c499b1ec234c401f68fe1}` | [md](writeup-osint-paper-lanterns.md) |
| pwn | Encore | 500 | ✅ solved | `safctf{a6aca5b356ad7824a01d0a767b2cd998}` | [md](writeup-pwn-encore.md) |
| pwn | Moonbase Radio | 500 | ✅ solved | `safctf{d8e20273d4d4cd65472f84b4316666eb}` | [md](writeup-pwn-moonbase-radio.md) |
| pwn | Overtime | 320 | ✅ solved | `safctf{cd00df957d06e810a0cd860918f03bb7}` | [md](writeup-pwn-overtime.md) |
| pwn | Neon Cabaret | 300 | ✅ solved | `safctf{c6d2ec6a705f9a51db0be634224d3358}` | [md](writeup-pwn-neon-cabaret.md) |
| reverse | Prism Orchestra | 750 | ✅ solved | `safctf{406279bd-3201-499f-9a4a-f14e8918eb37}` | [md](writeup-rev-prism-orchestra.md) |
| reverse | Clockwork Ballet | 500 | ✅ solved | `safctf{93d4bf6a-b750-4379-9038-c4921872c148}` | [md](writeup-rev-clockwork-ballet.md) |
| reverse | Pixel Courier | 150 | ✅ solved | `safctf{e7802274-4b04-488a-9319-39ca86e83c9f}` | [md](writeup-rev-pixel-courier.md) |
| web | Citrus Proof | 750 | ✅ solved | `safctf{83f575a861a0c69d675d700dcb658cd2}` | [md](writeup-web-citrus-proof.md) |
| web | Backstage Ledger | 500 | ✅ solved | `safctf{414329f08fe10f2027b4afeb2e5bba9b}` | [md](writeup-api-backstage-ledger.md) |
| web | Velvet Rehearsal | 500 | ✅ solved | `safctf{1745c9cc8a433522796feb9cfb8275de}` | [md](writeup-web-velvet-rehearsal.md) |
| web | Inner Joiner | 450 | ⚠️ no flag | — | [md](writeup-web-inner-joiner.md) |
| web | Midnight Feedback | 450 | ✅ solved | `safctf{f0e94a82-6662-4649-8b44-cb6fd2f8323a}` | [md](writeup-web-midnight-feedback.md) |
| web | Secret Vault | 450 | ✅ solved | `safctf{7877e854c9f06a8362af26ee280a6574}` | [md](writeup-web-secret-vault.md) |
| web | Tomcat Path Traversal | 450 | ✅ solved | `safctf{e9e46fabe7b282f4eb4eff39b378eff3}` | [md](writeup-web-tomcat-path-traversal.md) |
| web | You Snitch | 450 | ✅ solved | `safctf{73c4979d1dccb358dbfbaca5233666ca}` | [md](writeup-web-you-snitch.md) |
| web | Lightweight Directory | 400 | ✅ solved | `safctf{ef30111b835006ade7f00a9a4526d453}` | [md](writeup-web-lightweight-directory.md) |
| web | Photo Finish | 400 | ⚠️ no flag | — | [md](writeup-api-photo-finish.md) |
| web | Ginger Juice Shop | 350 | ✅ solved | `safctf{42dd8c3f359acdfc9b4250f4864ffc35}` | [md](writeup-web-ginger-juice-shop.md) |
| web | Internal Affairs | 300 | ✅ solved | `safctf{9f3a458f3a26e6372b5b5467e3e51edf}` | [md](writeup-web-internal-affairs.md) |
| web | Know Your Limits | 300 | ✅ solved | `safctf{30f33ad5be8abc02f034b5b266ff6b81}` | [md](writeup-web-know-your-limits.md) |
| web | Night Bus | 300 | ✅ solved | `safctf{81a90dc817371a5aa190e8069ebcde2c}` | [md](writeup-api-night-bus.md) |
| web | Prompt Pirate | 300 | ✅ solved | `safctf{4d19e2980e16abb93f0ff0481e4729e1}` | [md](writeup-web-prompt-pirate.md) |
| web | SSTI Secrets | 300 | ✅ solved | `safctf{287a681f8f9aa898e0743b5b392952b0}` | [md](writeup-web-ssti-secrets.md) |
| web | Templated Malice | 300 | ✅ solved | `safctf{ac4c0d4a503d4ef281530c5ca9dc8fa4}` | [md](writeup-web-templated-malice.md) |
| web | Touchline Dispatch | 300 | ✅ solved | `safctf{276928973c4dea42f63d808ba7be66b7}` | [md](writeup-web-touchline-dispatch.md) |
| web | Upload Your Art | 300 | ✅ solved | `safctf{059507cb1ce1b9fa4dbf4ad6cfb83a4a}` | [md](writeup-web-upload-your-art.md) |
| web | Archived | 250 | ✅ solved | `safctf{960c0e8a73c24bd9b1aee314ded96157}` | [md](writeup-xxe-archived.md) |
| web | HEAD Office | 250 | ✅ solved | `safctf{e657eef1b0b097c60911f62cfe4ec61b}` | [md](writeup-web-head-office.md) |
| web | JWT Forgery | 150 | ✅ solved | `safctf{1e4d7bdea93b47c2a813ea5a89f20870}` | [md](writeup-web-jwt-forgery.md) |
| web | Mr Beast Configuration | 150 | ⚠️ no flag | — | [md](writeup-web-mr-beast-configuration.md) |
| web | Quick Recovery | 150 | ✅ solved | `safctf{69f779b5b18bad69606f1926395e7c2a}` | [md](writeup-web-quick-recovery.md) |
| web | Sneaky Includes | 150 | ✅ solved | `safctf{9fdb535dbf8020d488bf8d6a51287778}` | [md](writeup-web-sneaky-includes.md) |

## Tools that did the work

Aggregated across the solves. Primary driver was Python 3 (stdlib + `requests`); category-specific tooling below.

| Area | Tools |
| --- | --- |
| Web / API / XXE | curl, Burp Suite, ffuf/feroxbuster, sqlmap, jwt_tool, tplmap, pyzbar (QR) |
| Cloud | aws CLI, kubectl, Pacu, ScoutSuite |
| Crypto | PyCryptodome, `cryptography`, SageMath, z3, sympy/gmpy2, fpylll |
| Forensics | Wireshark/tshark, Volatility 3, binwalk, exiftool, zsteg, custom pcap parsers |
| Mobile | jadx, apktool, Frida/objection, dex2jar, adb, keytool |
| Pwn | pwntools, GDB+pwndbg/GEF, Ghidra, radare2, ROPgadget, one_gadget, checksec |
| Reverse | Ghidra, IDA, radare2/rizin, angr, GDB, custom VM emulators |
| OSINT | exiftool, Wayback Machine, Google/GitHub dorking, sherlock/maigret, reverse image search |
| AD | BloodHound/SharpHound, Certipy, impacket, ldapsearch |
| Recon | nmap, full-range TCP sweeps, openssl/testssl.sh, jq |

> Writeups are regenerated from `chal/*/NOTES.md` + `solve.py` by `generate_writeups.py`; the six hand-authored entries (orchard-society, long-exposure, midnight-feedback, photo-finish, mr-beast-configuration, inner-joiner) are kept out of that map and edited directly.
