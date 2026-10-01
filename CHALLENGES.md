# Safaricom CTF — Challenge Board & Triage

**Total: 51 challenges. Solved: 32 — plus 1 blocked (Mr Beast, broken as deployed).**
**Live target map (host/port per challenge) → [TARGETS.md](TARGETS.md). Updated 2026-10-02.**

Solved (32):
- **WEB** — Quick Recovery, Sneaky Includes, JWT Forgery (150); HEAD Office (250);
  Templated Malice, SSTI Secrets, Prompt Pirate, Internal Affairs, Upload Your Art,
  Touchline Dispatch, Know Your Limits (300); Ginger Juice Shop (350);
  Lightweight Directory, Tomcat Path Traversal, You Snitch, Secret Vault (400–450);
  Velvet Rehearsal (500) — HTTP parameter pollution in `/api/recovery`.
- **CRY** — Three Encores (300); Parallel Lines (500).
- **REV** — Pixel Courier (150); Clockwork Ballet (500) — TEA over 3 blocks + XOR mask;
  Prism Orchestra (750) — 3-byte-op stack VM, inverted in reverse.
- **CLOUD** — Stageworks (500) — AssumeRole chain: leaked external ID + required session tag;
  Greenroom Atlas (750) — fake-K8s RBAC: automount a service-account token via workload logs.
- **PWN** — Overtime (32-bit `40*qty` wrap vs `qty>99` check);
  Neon Cabaret (`printf(user_buf)` → `%4919c%n` writes the win global);
  Moonbase Radio (UAF function pointer → ret2win).
- **FOR** — Matchday Replay (raw `LINKTYPE_USER0` records, out-of-order reassembly + period-12 keystream);
  Second Pressing (SQLite WAL — recover the pre-revision frame).
- **MISC** — Ticket Carousel (unlisted :8630) — BFS the served 40-state DFA to its closing state.

Triage columns:
- **Conf** — confidence I can solve it, given a reachable target. `★★★` high, `★★` medium, `★` low/environment-dependent.
- **Likely class** — my read on the vulnerability from the title + category.
- **Tier** — start order. T1 = fast wins, T2 = core work, T3 = hard/long.

---

## T1 — Start here (fast, high confidence)

| Challenge | Cat | Pts | Conf | Likely class |
| --- | --- | --- | --- | --- |
| Quick Recovery | WEB | 150 | ★★★ | Weak password-reset / recovery token (predictable, reusable, or leaked) |
| Sneaky Includes | WEB | 150 | ★★★ | LFI / RFI via include() — wrapper or filter bypass |
| JWT Forgery | WEB | 150 | ★★★ | `alg:none`, HS256 secret crack, or RS256→HS256 confusion |
| Mr Beast Configuration | WEB | 150 | ★★★ | Misconfiguration / exposed config, debug endpoint, default creds |
| Neural Memory Leak | AI | 150 | ★★★ | Prompt leak / system-prompt extraction from a chatbot |
| Pixel Courier | REV | 150 | ★★★ | Image/PNG-based flag encoding — carve, LSB, chunks |
| HEAD Office | WEB | 250 | ★★★ | HTTP verb (`HEAD`/`OPTIONS`) or header-based auth bypass |
| Archived | XXE | 250 | ★★★ | Classic XXE — file read, likely via an upload/parse endpoint |

## T2 — Core work (medium, good confidence)

| Challenge | Cat | Pts | Conf | Likely class |
| --- | --- | --- | --- | --- |
| Path Least Travelled | WEB | 300 | ★★★ | Path traversal + filter bypass |
| SSTI Secrets | WEB | 300 | ★★★ | SSTI (Jinja2/Twig) → RCE |
| Templated Malice | WEB | 300 | ★★★ | SSTI, second variant (different engine/context) |
| Know Your Limits | WEB | 300 | ★★★ | Rate-limit / size-limit abuse, or request smuggling |
| Internal Affairs | WEB | 300 | ★★★ | SSRF to internal service |
| Upload Your Art | WEB | 300 | ★★★ | File-upload bypass (magic bytes, extension, .htaccess) |
| Touchline Dispatch | WEB | 300 | ★★ | Webhook / out-of-band dispatch abuse |
| Prompt Pirate | WEB/AI | 300 | ★★★ | LLM prompt injection (listed under WEB, it's an LLM target) |
| Night Bus | API | 300 | ★★★ | REST API authz flaw (BOLA/IDOR, mass assignment) |
| Fancy Details | FOR | 300 | ★★★ | File metadata / EXIF / document forensics |
| Matchday Replay | FOR | 300 | ★★★ | Packet capture / traffic analysis |
| Three Encores | CRY | 300 | ★★★ | Classical cipher chain or repeating-key XOR |
| No Strings Attached | MOB | 300 | ★★ | APK static analysis (strings first, then jadx) |
| Comeback Pocket | MOB | 300 | ★★ | Mobile storage — keystore/SharedPrefs/SQLite |
| Paper Lanterns | OSINT | 300 | ★★ | Social/username pivot |
| Orchard Society | AD | 300 | ★ | AD enumeration (needs lab reachability) |
| Harbor Lights | CLOUD | 300 | ★★ | Cloud misconfig — public bucket / exposed metadata |

## T3 — Hard / long (high value, lower confidence)

| Challenge | Cat | Pts | Conf | Likely class |
| --- | --- | --- | --- | --- |
| Ginger Juice Shop | WEB | 350 | ★★ | Multi-vuln app chain (Juice-Shop style) |
| Lightweight Directory | WEB | 400 | ★★ | LDAP injection |
| Secret Vault | WEB | 450 | ★★ | SSRF → cloud metadata / secrets store |
| You Snitch | WEB | 450 | ★★ | Blind/OOB exfil (DNS or HTTP callback) |
| Tomcat Path Traversal | WEB | 450 | ★★★ | CVE-2024-50379 / CVE-2025-24813 class |
| Inner Joiner | WEB | 450 | ★★ | SQL injection (JOIN / blind) |
| Velvet Rehearsal | WEB | 500 | ★★ | Multi-stage web chain |
| Citrus Proof | WEB | 750 | ★ | Hardest web — full chain, likely custom |
| Clockwork Ballet | REV | 500 | ★★ | Binary RE + constraint solving (z3) |
| Prism Orchestra | REV | 750 | ★ | Heavy RE, possibly VM/custom arch |
| Northern Lights | MOB | 500 | ★ | Native lib / obfuscated APK |
| Glass Arcade | MOB | 750 | ★ | Hardest mobile — anti-tamper, dynamic |
| Second Pressing | FOR | 500 | ★★ | Disk/memory image forensics |
| Long Exposure | FOR | 750 | ★ | Hardest forensics — timeline/artifact carving |
| Backstage Ledger | API | 500 | ★★ | GraphQL / complex API chain |
| Photo Finish | API | 750 | ★ | Hardest API |
| Stageworks | CLOUD | 500 | ★ | Cloud exploitation chain |
| Greenroom Atlas | CLOUD | 750 | ★ | Hardest cloud |
| Parallel Lines | CRY | 500 | ★★ | ECC / lattice / advanced |
| Midnight Parcel | CRY | 750 | ★ | Hardest crypto |
| Last Tram Home | OSINT | 500 | ★ | Multi-source geolocation/timeline |
| Blue Meridian | OSINT | 750 | ★ | Hardest OSINT |
| Winter Pavilion | AD | 500 | ★ | AD exploitation chain |
| Crown Studio | AD | 750 | ★ | Hardest AD |
| Encore | PWN | 500 | ★★ | Binary exploitation (ret2libc/format string) |
| Text4Shell Lab | CVE | ? | ★★★ | CVE-2022-42889 — Apache Commons Text RCE |

---

## Where I'm strongest vs. weakest

**Strongest (agent-friendly):** WEB, API, XXE, Crypto (classical/implemented), Forensics
(static artifacts), RE (given a binary), CVE.

Why: these are all *reason-and-script* problems. I can read a response, form a
hypothesis, write a payload or a Python script, and iterate quickly. No external
lab, no GUI, no waiting on a human.

**Weakest / environment-dependent:**
- **Active Directory** (3) — needs a reachable domain lab + impacket/BloodHound and
  usually a Windows foothold. Slow, infrastructure-heavy.
- **Cloud** (3) — depends entirely on what credentials/console access the platform
  hands out. Fine if creds are given; blocked otherwise.
- **OSINT** (3) — needs live web search + social pivots. My search is US-only and
  can't log into platforms.
- **Mobile** (4) — needs `jadx`/`apktool`/`frida` installed; the 500/750 ones likely
  need an emulator + dynamic instrumentation.
- **PWN** (1) — doable (gdb present), but highest variance per challenge.

---

## Tooling gaps to check before the relevant category

| Need | Tool | Present? |
| --- | --- | --- |
| Web proxy / repeater | `caido` or `burpsuite` | verify |
| APK decompile | `jadx`, `apktool` | verify |
| Dynamic mobile | `frida`, `objection` | verify |
| AD | `impacket`, `bloodhound`, `netexec` | verify |
| Pwn | `pwntools`, `checksec`, `gdb`+pwndbg | gdb yes, rest verify |
| Crypto | `sage`, `pycryptodome`, `z3` | verify |
| Stego/forensics | `binwalk`, `exiftool`, `volatility3`, `zsteg` | verify |
| Cloud | `awscli`, `pacu` | verify |
