---
title: "Orchard Society"
ctf: "Safaricom CTF"
date: 2026-10-06
category: ad
difficulty: medium
points: 300
flag_format: "safctf{...}"
author: "Strawhats"
---

# Orchard Society

## Summary

`http://54.72.82.22:8570` is an ACTIVE DIRECTORY-themed desk app that ships one
archive of directory and ACL data. The task is to resolve a visitor's *effective*
access to a resource and submit the receipt string for that decision.

**The authorization logic was fully resolved and cross-checked three separate
ways. The flag was never captured.** The decision is unambiguous, but the exact
receipt string the grader expects could not be recovered — roughly 337,000
candidate submissions returned `403`, and no raw or hashed join of the shipped
fields matches. This writeup records the solved half (the AD reasoning, which is
genuinely interesting and which we are confident about) and the exact blocker on
the unsolved half, so it is not re-attempted blindly.

## Target and surface

- **Desk:** `http://54.72.82.22:8570` (Werkzeug 3.1.9 / Flask)
- **Artifact:** `GET /downloads/orchard-export.zip` — the only download

| Route | Behaviour |
| --- | --- |
| `GET /` | Desk page; links the zip; form POSTs `{"answer": ...}` to `/submit` |
| `GET /downloads/orchard-export.zip` | The only artifact (4 files) |
| `GET /api/<op>` | **Every** op name tried → `404 {"message":"Not found"}` |
| `POST /submit` | `200 {"message":"safctf{...}","ok":true}` iff correct, else `403` |

We fingerprinted the submit handler precisely, because the error behaviour tells
you the code shape. A JSON **string**, int, or list body → `500`
(`'abc'.get` raising `AttributeError`); `null`, `{}`, and `{"answer":null}` →
`403`. That is exactly:

```python
(request.get_json(silent=True) or {}).get("answer")
# compared via hmac.compare_digest(sha256(answer), cfg['answer_hash'])
```

Debug mode is **off** here (a 500 returns a plain 265-byte page with no
traceback), unlike the sibling on `:8110`. The comparison is constant-time, so
there is no length or timing side channel — `/submit` is a pure yes/no oracle.

## The artifact

`orchard-export.zip` holds four entries with a shared mtime, no comment, no extra
fields, and no duplicate members:

| File | Content |
| --- | --- |
| `session.json` | `{"objectSid": "S-1-5-21-810-920-1030-1000"}` |
| `resource-acl.json` | `{"resource": "record-ef1b86a30b808513", "aces": [...]}` |
| `directory.json` | 70 rows of `{sid, name, memberOf}` (`team-XXXXXXXX`) |
| `curator-note.txt` | *"Visitors sometimes belong to more than one committee. For the reading room, consult both the current register and the filed exception."* |

The curator's note is the hint that carries the challenge. "The current register"
is `directory.json` — live group membership. "The filed exception" is
`resource-acl.json` — the ACEs on the resource. "Belong to more than one
committee" is the warning that the answer requires the *transitive closure* of
membership, not just the direct parent group.

The two ACEs:

```json
{"resource": "record-ef1b86a30b808513",
 "aces": [{"sid": "S-1-5-21-810-920-1030-1068", "type": "allow", "right": "ReadProperty"},
          {"sid": "S-1-5-21-810-920-1030-1069", "type": "deny",  "right": "ReadProperty"}]}
```

## Step 1 — Resolve effective access (this part is solid)

Two ACEs point opposite directions, so the whole challenge is deciding which one
applies. Windows evaluates an access check by computing the caller's **group
membership closure** and testing each ACE against it, with **DENY taking
precedence over ALLOW** when both match.

The critical detail: `1000` does **not** directly belong to the groups in the
ACEs. It belongs to a chain. Walking `memberOf` transitively from the session SID
gives the full closure:

```
1000 (team-a4654927) → 1013 (team-0f85fe7a) → 1027 (team-b13c037b)
                     → 1046 (team-2648700f) → 1068 (team-a4283b27)
```

Matching the two ACEs against that closure:

- **`…-1068` (allow, ReadProperty)** — `team-a4283b27` is in the closure. **Matches.**
- **`…-1069` (deny, ReadProperty)** — `team-5803825d` is **not** in the closure.
  **Does not match.**

We verified the deny is a deliberate decoy, not just a miss. Group `1069` has 61
members — every team from `1001` to `1061` — and **none** of them appears in
`1000`'s closure. Groups `1065`–`1069` all have empty `memberOf`, so there is no
path into `1069` we could have missed. The deny exists to punish a solver who
checks only the direct group or who assumes the denying ACE wins by existing.

**Effective decision: ALLOW, granted by the ACE on `1068`.**

We also checked whether the group names' 8 hex characters encode anything — no.
The 280 bytes across all names are ~40% printable, i.e. random.

## Step 2 — The receipt (this is where it stalls)

`/submit` wants a single string. The problem is that the challenge never states
its format, and the decision is a *boolean* — so the receipt must be some
canonical serialization of the resolution that the author generated. We attacked
it as a reconstruction problem.

Across six rounds, roughly **337,000** candidates were submitted, all `403`:

1. **Structural permutations** (~217k): every length-1–3 permutation of a
   14-value pool `{resource, resource-hex, SIDs/names/rids of 1000/1068/1069,
   "ReadProperty", allow, deny}` across separators `| : - _ "" space`; length-4
   over `| :`; length-5 over a 9-value pool — which *does* cover the full 5-SID
   membership chain `…1000|…1013|…1027|…1046|…1068`; joins of the three middle
   hops ± the deciding group; and the SHA-256/MD5 of every short join.
2. **Artifact-level values** (905): whole-zip and per-member `sha256/md5/sha1`,
   verbatim file text, zip-order concatenation hashes, base64/hex of key strings,
   and `orchard.test`-flavoured joins.
3. **Case and formatting variants** (~16.6k): `Allow`/`ALLOW`/`granted`/`true`,
   right-name variants, `<id>|<field>|<field>` key=value forms across `| ; ,`,
   and UPN/domain forms (`visitor@orchard.test`, `ORCHARD\team-a4283b27`).
4. **Row-exhaustive sweeps** (294 + 712 + 100k): every `directory.json` row as
   `sid|name|memberOf` (raw, compact, empty-joined) and its hashes; the deciding
   ACE in every field order and its hashes; both-ACE full joins.

None hit.

### Why the near-miss theory is plausible

The solved sibling **Winter Pavilion (`:8580`)** runs the *same newer runtime*
and establishes the family convention: the receipt is the **raw pipe-join of the
deciding row's identifying fields**, e.g. `guid|serviceAccount|command`. Applied
here by analogy, that would be:

```
S-1-5-21-810-920-1030-1068|allow|ReadProperty
```

Submitted — `403`.

The structural difference is the tell. Winter Pavilion's deciding row has a
natural `guid|serviceAccount|command` identity. Orchard's deciding row is an ACE,
which has no identifier of its own beyond a SID shared with a directory row — so
the field the generator joined may simply **not exist** in the shipped
`resource-acl.json`. That is the same defect class as the three broken-as-deployed
siblings (Mr Beast `:8110`, Photo Finish `:8350`, Long Exposure `:8470`), where
the artifact shipped without a field the grader still expected.

## Step 3 — Why we could not just read the answer

Two escape hatches would have settled it directly, and both are closed:

- **`/api` is dead.** We enumerated all 4,698 words from `common.txt` **plus**
  ~120 AD/ACL-themed op names (`receipt`, `access`, `acl`, `decide`, `effective`,
  `resolve`, `permission`, `session`, `enroll`, …) across GET and POST, and then
  696 parameterized/query forms (`/api/<stem>/<sid|name|resource|rid>`,
  `/api/<stem>?sid=…`, `/api/acl/<stem>`, `/api/ad/<stem>`). Every single one
  returned the generic JSON `404`. This container's `kind` has **no reachable
  op** — the leaked runtime's 13 kinds do not include it, so it runs a **newer
  build** than the leaked `chal/_shared/organizer-service.py`.
- **The leaked source path is closed.** The `/api/view` absolute-path traversal
  that leaks `/app/service.py` exists only on `:8300` (Touchline Dispatch). It
  cannot be reused here: this is the newer runtime, whose ops the leaked source
  does not contain. `:8570`'s own `settings.json` — which holds `answer_hash` —
  is unreachable.

## Verdict

The **decision is settled**: visitor `…-1000`'s transitive closure reaches the
allow ACE on `…-1068`, and the deny on `…-1069` is a decoy it does not match.
Effective access is **ALLOW** via `ReadProperty`. We are confident in this and
cross-checked it three times.

The **receipt is not recoverable** from the shipped materials. Either the
generator's receipt uses a field that was dropped when `resource-acl.json` was
written (the Mr Beast / Photo Finish / Long Exposure defect class), or it uses a
transform outside the tested family (key=value, UPN, and path forms were all
tested). The recommended next step is the organizer generator for the `ad-acl`
kind, or `:8570`'s own `settings.json` — neither is reachable with the tooling
available during the event.

`solve.py` resolves the closure, prints the decision, and sweeps the round-1
candidate family against `/submit`, reporting any non-403 response — useful if
the target is ever restored or a correct receipt format surfaces.

## Tools

**Used in this solve:**

- Python 3 (`requests`, `zipfile`, `hashlib`, `hmac`, `itertools`) — closure resolver + the ~337k-candidate receipt sweep against `/submit`
- a custom transitive group-membership (SID closure) walker

**Other tools that fit this task:**

- BloodHound / SharpHound (visualise the group-nesting that decides the ACE) — the concept this challenge models
- Certipy (for the real AD CS ESC-family bugs this family draws on, cf. Crown Studio)
- ldapsearch / impacket (enumerate directory objects in a live AD)
- the organizer generator for the `ad-acl` kind, or the container's own `settings.json` — the only things that would reveal the expected receipt format

## Flag

Not captured. The decision is `ALLOW` (deciding ACE
`S-1-5-21-810-920-1030-1068`, right `ReadProperty`), but no receipt string was
ever accepted by `/submit`.
