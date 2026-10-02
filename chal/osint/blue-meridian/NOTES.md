# Blue Meridian — OSINT, 550 pts

Target: http://54.72.82.22:8500 (Flask/Werkzeug desk app)

## Surface
- `GET /` — landing page, "Collection desk" linking `GET /downloads/field-notes.zip`
- `GET /submit` → 405, `POST /submit {"answer": ...}` → 200 graded flag (desk app confirmed)

The page copy ("a single line cuts quietly across the familiar landscape") is the
hint for the *bearing* field; the puzzle itself lives entirely in the zip.

## The zip (field-notes.zip, 3857 B)
| file | role |
|---|---|
| `camera-metadata.json` | the identifier: `local_time 2026-06-04T21:00:00`, `utc_offset +02:00`, `compass_degrees 11`, `vessel_mark vessel-3` |
| `voyages.json` | 60 voyages: `ref, vessel, station, utc_hour, tide_cm, bearing` |
| `tide-station.csv` | station -> tide_cm (decoy-ish; keyed by the same station refs) |
| `civic-directory.json` | 36 houses keyed by the same station refs — pure decoy |
| `pier-note.txt` | "At the exposure, the gauge was 219 cm. Clock and compass had both been serviced that morning." (confirms clock/bearing are uncorrupted → use raw values) |
| `submission.txt` | receipt format `SHA256(voyage_ref\|station_ref\|UTC_time)` lowercase hex, `UTC_time` = `HH:MMZ` |

## Resolution
Filter `voyages.json` on the three camera fields:
`vessel == vessel-3`, `bearing == 11`, plus UTC hour from local+offset
(21:00 +02:00 → 19:00Z). Exactly one row matches:

```
{"ref": "d0b36031a079e290", "vessel": "vessel-3", "station": "5255073ff2",
 "utc_hour": 19, "tide_cm": 219, "bearing": 11}
```

`tide_cm 219` matches the pier-note gauge reading — a cross-check, not an input.

Receipt = `sha256("d0b36031a079e290|5255073ff2|19:00Z")`
        = `a037d4fd49143de5d5abbe38b536198ba777879089dd3b44dec83ac1b962c845`

`POST /submit {"answer": "<receipt>"}` → `200 {"message":"safctf{756f7d81426571a6d6dac9b1aae5f271}","ok":true}`

## Notes / gotchas
- No exploitation needed — the "OSINT" framing is flavour; the joining key is the
  shared `station`/`ref` namespace across the JSON/CSV files.
- The intermediate (the receipt hash) is accepted directly; the desk returns the
  graded `safctf{...}` flag.
- `field-notes.zip` is a binary and git-ignored; not committed.
  URL: `http://54.72.82.22:8500/downloads/field-notes.zip`
  SHA256: `659e0d481bb797d1474031c43ba2236fc2d8cc477b56dd8fb7789aa657466c89`

## Flag
`safctf{756f7d81426571a6d6dac9b1aae5f271}`
