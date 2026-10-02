# Orchard Society — ACTIVE DIRECTORY, 300 pts

- **Target:** `http://54.72.82.22:8570` (Werkzeug 3.1.9 / Flask, desk app of the
  family runtime, but a **newer** build than the leaked `:8300` source)
- **Status:** ❌ UNSOLVED — decision fully resolved, receipt string not found
  (~337k submissions, all 403). See "Verdict".

## App surface

| Route | Behaviour |
| --- | --- |
| `GET /` | desk page, links `/downloads/orchard-export.zip`; form POSTs `{"answer": ...}` to `/submit` |
| `GET /downloads/orchard-export.zip` | the only artifact (4 files) |
| `GET /api/<op>` | **every** op name tried → `404 {"message":"Not found"}` |
| `POST /submit` | `200 {"message":"safctf{...}","ok":true}` iff correct, else `403 {"message":"The request could not be completed.","ok":false}`; `GET` → 405 |

Handler fingerprint (matches the family runtime exactly): a JSON **string**,
int or list body → **500** (`'abc'.get` → AttributeError); `null` / `{}` /
`{"answer":null}` → 403. i.e. `(request.get_json(silent=True) or {}).get("answer")`
compared with `hmac.compare_digest(sha256(answer), cfg['answer_hash'])`. Debug is
**off** (a 500 returns the plain 265-byte page, no traceback), unlike `:8110`.

`/api` op enumeration: all 4,698 `common.txt` words **and** ~120 AD/ACL-themed
op names (`receipt`, `access`, `acl`, `decide`, `effective`, `resolve`,
`permission`, `session`, `enroll`, …) × GET+POST, **plus 696 parameterized /
query forms** (`/api/<stem>/<sid|name|resource|rid>`, `/api/<stem>?sid=…`,
`/api/acl/<stem>`, `/api/ad/<stem>`) — every one returns the generic JSON 404, so
this container's `kind` has **no reachable op**. `/downloads/` holds only
`orchard-export.zip` (60 filenames probed). The `:8300` `/api/view` traversal
cannot be reused here (this is a different, newer runtime — see below).

## Artifact

`orchard-export.zip` — 4 entries, shared mtime, no comment/extra, no duplicates.

| file | content |
| --- | --- |
| `session.json` | `{"objectSid": "S-1-5-21-810-920-1030-1000"}` |
| `resource-acl.json` | `{"resource": "record-ef1b86a30b808513", "aces": [{"sid": "…-1068", "type": "allow", "right": "ReadProperty"}, {"sid": "…-1069", "type": "deny", "right": "ReadProperty"}]}` |
| `directory.json` | 70 rows `{sid, name, memberOf}` (`team-XXXXXXXX`) |
| `curator-note.txt` | *"Visitors sometimes belong to more than one committee. For the reading room, consult both the current register and the filed exception."* |

## The AD logic (unambiguous, cross-checked 3×)

Membership closure of the session SID `…-1000`:

```
1000 (team-a4654927) → 1013 (team-0f85fe7a) → 1027 (team-b13c037b)
                     → 1046 (team-2648700f) → 1068 (team-a4283b27)
```

`1069` (team-5803825d, the deny ACE) has 61 members — every other team
(`1001…1061`) — and **none** of them is in `1000`'s closure. `1065–1069` have
empty `memberOf`. So the effective decision is **ALLOW**, granted by the ACE on
**1068**; the deny on 1069 is a decoy for the other visitors.

None of the names' 8 hex chars hide anything (280 bytes, ~40 % printable = random).

## What was submitted (all 403)

`POST /submit` totals ≈ **337,000** candidates:

1. **round 1** (`solve.py`, 217,296 cands): the raw ACE/ACL JSON; all len 1–3
   permutations of a 14-value pool `{resource, resource-hex, SIDs/names/rids of
   1000/1068/1069, "ReadProperty", allow, deny}` with separators `| : - _ "" space`;
   len 4 over `| :`; len 5 over a 9-value pool (this **does** cover the full
   5-SID chain `…1000|…1013|…1027|…1046|…1068`); chain joins of the 3 middle
   hops ± the deciding group; `sha256`/`md5` of every short join; JSON and
   wrapper forms — 0 hits.
2. **extras** (905): whole-zip and per-member `sha256/md5/sha1`, verbatim file
   text, zip-order concatenation hashes, `base64`/hex of key strings,
   `orchard.test`-flavoured and deny-flavoured joins — 0 hits.
3. **round 3** (16,644): case variants (`Allow`/`ALLOW`/`granted`/`true`),
   right-name variants, `<id>|<field>|<field>` **key=value** forms (`|` `;` `,`),
   UPN/domain forms (`visitor@orchard.test`, `ORCHARD\team-a4283b27`), 4-perms
   over a domain-expanded pool, 5-name and 5-SID chains ± `allow`/`ReadProperty`,
   and hashes of all of the above — 0 hits.
4. **round 4/5/6** (294 + 712 + 100k): every `directory.json` row as
   `sid|name|memberOf` (raw/compact/empty/joined) and its hashes; the deciding
   ACE in every field order and its hashes; both-ACE full joins; 5-perms of a
   10-value pool with `|` and `:` — 0 hits.

## Verdict

The decision is settled and the receipt is *not* any raw or hashed join of the
materials' fields. The sibling **Winter Pavilion (:8580, same newer runtime,
solveable)** shows the family convention: the flag arrives from `/submit` and the
receipt is the **raw pipe-join of the deciding row's identifying fields**
(`guid|serviceAccount|command`). Applied here that is
`S-1-5-21-810-920-1030-1068|allow|ReadProperty` — submitted, 403.

So one of: (a) the generator's receipt uses a field that was **dropped** from
`resource-acl.json` when the artifact was written (the same defect class as
`Mr Beast` :8110, `Photo Finish` :8350, `Long Exposure` :8470), or (b) it uses a
transform outside the tested family (key=value / UPN / path forms all tested).
Recommended next step is the **organizer generator** for the `ad-acl` kind, or
`:8570`'s own `settings.json` (`answer_hash`) — neither is reachable: the
`web-path` traversal that leaks `/app/service.py` exists only on **:8300**, and
this container runs the newer runtime whose kinds/ops the leaked source does not
contain.

## Reproduce

```
/home/nomad/safaricom_ctf/.venv/bin/python chal/ad/orchard-society/solve.py
```

`solve.py` resolves the closure, prints the decision, and sweeps the round-1
candidate family against `/submit`, reporting any non-403 response.
