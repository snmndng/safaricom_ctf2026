# Double Feature — MISC, 400 pts

- **Target:** http://54.72.82.22:8640 (Werkzeug / Python — the shared family runtime, kind `misc-zip`)
- **Status:** ✅ SOLVED — flag `safctf{513195eb399c59321e043c54773185b7}`

## Surface

| Route | Behaviour |
| --- | --- |
| `GET /` | desk page ("Double Feature" / "Two screens, one very good evening.") linking `/downloads/sample.zip` |
| `GET /downloads/sample.zip` | 152 B zip holding exactly one file: `show.json` = `{"mode": "preview", "stage": "foyer"}` |
| `POST /api/import` | `{"bundle": "<base64 zip>"}` — the graded endpoint |
| `GET /health` | `{"status":"ok"}` |

`GET /api/import` and `POST /api/import {}` both return
`{"message":"Request unavailable."}` — **400 from the dispatcher's exception
handler**, not the `{"message":"Not found"}` 404 of an unknown op. That is the
tell that the `import` op exists and only the missing `bundle` key raised.

## The bug (duplicate zip members)

Server logic (identical to `kind=='misc-zip'` in the leaked organizer runtime,
`chal/_shared/organizer-service.py`):

```python
raw = base64.b64decode(d['bundle']); z = zipfile.ZipFile(io.BytesIO(raw))
entries = z.infolist()
if len(entries) > 12:                          return reject
first = next(x for x in entries if x.filename == 'show.json')
if json.loads(z.read(first))['mode'] != 'preview':   return reject
last  = json.loads(z.read('show.json'))
return ok if last['mode'] == 'publish' and last['stage'] == 'main'
```

The two reads resolve **different entries**:

- `z.read(first)` is handed a `ZipInfo`, so it reads *that exact member*;
- `z.read('show.json')` is handed a **name**, and `NameToInfo` maps a name to the
  **last** member that used it.

A zip may legally carry duplicate filenames. So a two-member archive passes both
guards with contradictory contents:

```
entry 1  show.json  {"mode":"preview","stage":"foyer"}   -> first gate
entry 2  show.json  {"mode":"publish","stage":"main"}    -> final gate
```

## Reproduce

```
/home/nomad/safaricom_ctf/.venv/bin/python solve.py
```

→ `200 {"message":"safctf{513195eb399c59321e043c54773185b7}","ok":true}`

## Notes

- This identifies the previously *unmapped* `misc-zip` kind: it is **Double
  Feature :8640**. (The other unmapped kind, `api-canonical`, is still unplaced.)
- `zipfile` emits a `UserWarning: Duplicate name` when writing the bundle —
  harmless; the server reads it back without complaint.
- The desk app's `/submit` is a decoy here: the flag comes from `/api/import`,
  consistent with the sibling `misc-machine` (Ticket Carousel) and
  `crypto-oracle` (Midnight Parcel) kinds which also grade on their own op.
