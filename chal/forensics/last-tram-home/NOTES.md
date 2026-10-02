# Last Tram Home — OSINT (300)

**Flag:** `safctf{a7290ed4a3ba7af7bd4b4c529eb99314}`

## Endpoint
- Desk app: `http://54.72.82.22:8490`
- `GET /` — desk page linking `/downloads/field-notes.zip`
- Finale: `POST /submit {"answer":"<receipt>"}` → `200 {"message":"safctf{...}","ok":true}`

## Artifact
- `http://54.72.82.22:8490/downloads/field-notes.zip`
- sha256 `d70f0ace459bf26e7518bdf7ae4c79cdca50317415ebce1ef5b882532e3a655b`
- (binary kept out of git per repo .gitignore; extract manually with `unzip`)

Zip contents: `tram.csv`, `civic-directory.json`, `programme.json`,
`studio-post.txt`, `submission.txt`.

## Shape (same as Blue Meridian on :8500)
1. `studio-post.txt`: *"The last frame was taken at stop 18, three hours after
   UTC. The wall clock read 21:30 on 18 April 2026."*
   - local wall clock = UTC+3 → **UTC = 18:30 on 2026-04-18** (date unchanged).
2. `tram.csv`: `stop,venue` → stop **18** → venue_ref `b59c881fc2`.
3. `programme.json`: rows `{event, venue, time_utc, artist}`. Select the single
   row with `venue == b59c881fc2` **and** `time_utc == 2026-04-18T18:30:00Z`
   → event_ref **`2011bf1eeb4b`** (artist act-8). Exactly one match — no
   ambiguity, so no separate cross-confirm artifact was needed here.
4. `submission.txt`: *"Collection receipt format:
   SHA256(venue_ref|event_ref|UTC_date), lowercase hex."*
5. `receipt = sha256("b59c881fc2|2011bf1eeb4b|2026-04-18")`
   = `57aa623e8a9afd3082a959b18371e03ea717d6ad03f7e68948162fc507ee914d`
6. POSTed → flag.

## Notes / decoys
- `civic-directory.json` (venue metadata: name/district/roof/seats) is a decoy
  for the receipt — the hash does **not** use it. It is only a sanity anchor
  (ref `b59c881fc2` = "House 18", consistent with stop 18).
- `programme.json` repeats dates (April 1–20 then April 1–16 again) but
  `(venue, time_utc)` pairs are unique; the stop+time tuple uniquely selects
  the row, so the repeat-decoy does not bite.
- The key gotcha is the UTC conversion: wall clock 21:30 is local (UTC+3), so
  the matching `time_utc` is 18:30Z, **not** 21:30Z.

## Reproduce
```
python solve.py    # prints receipt and submits; expect ok:true + flag
```
