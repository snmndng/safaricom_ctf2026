# Shared organizer runtime (leaked)

`organizer-service.py` is the **organizer's own runtime source**, recovered from
`GET http://54.72.82.22:8300/api/view?name=/app/service.py` — Touchline Dispatch's
path traversal reads absolute paths, and `/app/service.py` is deployed into every
container of this family. Its own docstring says it: *"Isolated challenge runtime.
Organizer source; never served to players."*

**It is one file, parameterised by `settings.json`'s `kind`.** Each challenge in
the family is the same runtime with a different `kind` (and a different
`settings.json` holding that challenge's secrets — which this file does *not*
contain, since it reads them at runtime from its own container).

Read it before fuzzing any challenge below. Several of these were solved only
after brute force failed and the source was read instead.

## kind → challenge map

| `kind` | Challenge | Port | Note |
| --- | --- | --- | --- |
| `web-path` | Touchline Dispatch | 8300 | absolute-path traversal in `/api/view?name=` |
| `web-reset` | Velvet Rehearsal | 8310 | param pollution: recipient = first `member`, target = last |
| `web-render` | Citrus Proof | 8320 | JWK header key injection → curator → Jinja2 SSTI |
| `api-object` | Night Bus | 8330 | object = `sha256(reference)[:24]`; `next_reference` leaks the target |
| `api-merge` | Backstage Ledger | 8340 | `../` key escapes the profile merge into the parent user |
| `api-canonical` | *unmapped* | — | signed canonical JSON dispatch (`object_pairs_hook` reversal) |
| `cloud-store` | Harbor Lights | 8390 | `public/` prefix check bypassed by `posixpath.normpath` |
| `cloud-role` | Stageworks | 8400 | AssumeRole with leaked `external_id` + required session tag |
| `cloud-kube` | Greenroom Atlas | 8410 | RBAC PATCH → editor → workload automount → SA token |
| `crypto-oracle` | Midnight Parcel | 8440 | CBC padding oracle on `/api/receipt` |
| `misc-machine` | Ticket Carousel | 8630 | BFS the `transitions` DFA in settings.json |
| `misc-zip` | Double Feature | 8640 | duplicate zip members: `read(ZipInfo)` hits entry 1, `read(name)` hits entry 2 |
| `ad-certificate` | Crown Studio | 8590 | AD CS ESC1 — no approval + `supplySubject` + clientAuth |

One kind is still **unmapped** (`api-canonical`): it belongs to a challenge whose
port we have not identified. Its logic is in the source.

## Notes

- `FLAG` comes from the container env; `settings.json` may also carry it.
- `web-path` and `web-render` write `FLAG` to `private/reserve.txt` at startup.
- `/submit` compares `sha256(answer)` to `cfg['answer_hash']` — and when
  `settings.json` has **no** `answer_hash`, the fallback `'!'` can never match, so
  `/submit` 403s for every input by construction. That is why some challenges'
  `/submit` is a decoy.
