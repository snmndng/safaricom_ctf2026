# Winter Pavilion — ACTIVE DIRECTORY, 500 pts (board lists 350)

- **Target:** http://54.72.82.22:8580 (Werkzeug 3.1.9 / Python 3.11.16, Flask)
- **Status:** ✅ SOLVED — flag `safctf{8a97f3881e4828d37406ed0953ff9573}`
- **Category path:** `chal/ad/winter-pavilion/` (branch `chal/ad-winter-pavilion`)

## Receipt / flag

The effective GPO is computed by the AD rules below → linkOrder 15 (the only
`enforced:true` link, so the only one that survives `blockInheritance:true`,
and already `Crew`-filtered). The receipt is its three identifying fields
**pipe-joined**:

```
582dd884f15ee41330ceb416c60c6a1c|svc-620a984fb8|job-ee685b72ec4b
```

`POST /submit {"answer": "<above>"}` → `200 {"message":"safctf{8a97f3881e4828d37406ed0953ff9573}","ok":true}`

(`guid|serviceAccount|command` — *not* any hash and *not* any single field;
the raw-join is why the earlier single-field and hash-only sweeps all 403'd.)

## App surface (exhaustively fuzzed — only four routes exist)

| Route | Behaviour |
| --- | --- |
| `GET /` | Landing page ("WINTER PAVILION / ICE FESTIVAL", "Collection desk") linking the zip; a "Leave a receipt" form POSTs `{"answer": ...}` to `/submit`. The page JS still contains a vestigial "desk console" branch (`e.target.id === 'console'`) but **no console form is served**. |
| `GET /health` | `{"status":"ok"}` |
| `GET /downloads/pavilion-export.zip` | the only artifact (2125 B) |
| `POST /submit` | `{"answer": "<x>"}` → `200 {"message":"safctf{...}","ok":true}` iff correct, else `403 {"message":"The request could not be completed.","ok":false}`. `GET` → 405. |

Fuzzing performed (all 404 / JSON-404 only):
- ~14k paths (`/`, `/api/`, `/downloads/`, `/v1/`, `/v2/`, `/rpc/`, `/internal/`, `/svc/`, `/ws/`, `/ad/`, `/gp/`, `/gpo/`, `/policies/`) × GET+POST, with `common.txt` (4.75k words).
- `/api/<word>` for all 63k `raft-medium-words` (partial run) and `/api/<themed>` + `/api/<collection>/<id>` (~28k) — nothing.
- `/downloads/<name>` × 52k (words × extensions) — only `pavilion-export.zip` is 200.
- GUID-derived routes (`/api/<guid>`, `/<col>/<guid>`, `/downloads/<guid>.<ext>`, `/downloads/<sha256(ref)[:24]>.zip`, …) — nothing.
- Method sweep (PUT/PATCH/DELETE/OPTIONS/HEAD/TRACE), Host-header vhosts, ~20 spoofed IP/admin headers+cookies — nothing.
- Note the `/api/*` prefix has a JSON 404 handler (`{"message":"Not found"}`) while other unknown paths give the HTML 404 — a blueprint catch-all, but no route matched any word tried.

## Artifact (`pavilion-export.zip`) — 3 files, no `submission.txt`

Unlike every solved sibling desk app (blue-meridian, last-tram-home, paper-lanterns),
this zip ships **no receipt-format file** — there is no `submission.txt`, and
`scope.txt` is prose, not a recipe. The landing page states no format either.

```
gplink.json    35 GPO links
computer.json  {"ou":"OU=Stage,DC=pavilion,DC=test","groups":["Crew"],"blockInheritance":true}
scope.txt      "A recent renovation changed which local group can use the service wing.
                Facilities kept one central instruction in place throughout the work."
```

`gplink.json` rows: `{guid, linkOrder(1..35), enabled, securityFilter("Crew"|"Visitors"), enforced, serviceAccount("svc-<10hex>"), command("job-<12hex>")}`.

## The AD logic (unambiguous)

The rows are a **neat, periodic decoy list** (odd orders disabled, even enabled;
`securityFilter == Visitors` exactly when `linkOrder % 6 in {1,4}`), with **exactly one anomaly**:

```
linkOrder 15  guid 582dd884f15ee41330ceb416c60c6a1c  enabled=True  securityFilter=Crew  enforced=True
              serviceAccount svc-620a984fb8  command job-ee685b72ec4b
```

It is the only `enforced: true` row. AD rules ⇒ with `blockInheritance: true` the
non-enforced parent GPOs are blocked, **Enforced (No-Override) bypasses block
inheritance**, and it is security-filtered for the computer's only group (`Crew`).
So the GPO that applies is **#15** ("the one central instruction"), and nothing
was "meant to disappear" except by the enforced override.

## What was tried against `/submit` (≈600k submissions, all 403)

1. **Verbatim every field of every one of the 35 rows** — `guid` (raw/upper/dashed/braced),
   `serviceAccount` (with/without `svc-`, upper), `command` (with/without `job-`, upper),
   `linkOrder` (0–3000 as string *and* as JSON int), `securityFilter` ("Crew"/"Visitors"),
   `enabled`/`enforced` booleans. Result: none.
2. **Pairwise/triple joins** of those fields with `"" : - / | , space _ ; = @ \` — none.
3. **`safctf{<field>}` wrappers** (incl. dashed guid) — none.
4. **Hashes** `sha256/md5/sha1/sha512` of: each file's raw bytes; every row's single fields;
   ordered permutations (len 1–5) of `{guid, linkOrder, securityFilter, serviceAccount, command}`
   joined by `| : -`; permutations (len 1–3) of a 14-value pool (incl. `OU=Stage,DC=pavilion,DC=test`,
   `pavilion.test`, lowercase `true/false`, `Crew`); aggregate joins of applicable sets. — none.
5. **Well-known AD constants** — `{31B2F340-016D-11D2-945F-00C04FB984F9}` (Default Domain Policy),
   `{6AC1786C-016F-11D2-945F-00C04fB984F9}`, `gpLink` LDAP-path forms, `PAVILION\svc-…`. — none.
6. **Python type-juggling** (ints, floats, bools, `null`, list/dict) — 403 for all; a JSON
   *string* body gives 500 ⇒ the handler does `request.get_json().get("answer")` and compares
   with `==` (list/dict ⇒ 403, not a 400/500 membership TypeError).

## Where I'm stuck
Solved. Resolution: the receipt is the **raw pipe-join** of the effective GPO's
`guid|serviceAccount|command` — the earlier sweeps tried the individual fields
and *hashes* of joined fields but not the joined string itself.

## Reproduce

```
/home/nomad/safaricom_ctf/.venv/bin/python chal/ad/winter-pavilion/solve.py
```

`pavilion-export.zip` sha256: see `.zip.sha256` (binary kept out of git).
