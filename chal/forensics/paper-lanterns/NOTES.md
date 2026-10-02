# Paper Lanterns — OSINT, 200 pts

Desk: http://54.72.82.22:8480  (Werkzeug/3.1.9 Python/3.11.16)

## Result

- Flag: `safctf{38309964a77c499b1ec234c401f68fe1}`
- Submitted: `POST /submit` JSON `{"answer": "ba57ce94e3"}` -> `200 {"ok":true}`

## Deviation from the sibling template

The brief predicted: identifier in a note + local wall-clock/UTC-offset ->
convert to UTC -> CSV join -> JSON row -> `submission.txt` hash recipe.
**This challenge has none of that.** Specifically:

- No time component anywhere; no UTC conversion step.
- No second key / no CSV->JSON join by identifier. `districts.csv` is a
  4-row lookup (`district,river_side`) used only to decode the river word.
- No `submission.txt`, no stated hash recipe. The answer is the raw `ref`
  string, not a hash.
- `civic-directory.json` is NOT a decoy here — it is the actual target list.

## Endpoints / files

| Where | What |
|---|---|
| `GET /` | Desk page ("Collection desk" + "Leave a receipt" form) |
| `GET /downloads/field-notes.zip` | The only artifact. sha256 `6c3e8ba1537987f604331173138328a9cf76944fa0351d35465bc41ef66577a8` |
| `POST /submit` | `{"answer": ...}`; 200 `ok:true` only for the correct value, else 403 |
| `GET /submit` | 405 (confirms desk app, not WAF-blocked) |

Probed and 404: `/robots.txt`, `/sitemap.xml`, `/downloads/`, `/hint`,
`/notes`, `/api`, `/README`, `/static/`. Nothing else served.

## The solve

Zip contents: `postcard.txt`, `districts.csv`, `civic-directory.json` (36 rows).

`postcard.txt`:
> Lunch beneath a glass roof, somewhere east of the river. The brass plaque said 1997.

`districts.csv`: `North,north / East,east / South,south / West,west`

Three filters fall out of the prose:
- "glass roof" -> `roof == "glass"`
- "east of the river" -> `river_side == "east"` -> `district == "East"`
- "brass plaque said 1997" -> `opened == 1997`

Exactly one row in `civic-directory.json` satisfies all three:
`{"ref": "ba57ce94e3", "name": "House 18", "district": "East", "opened": 1997, "roof": "glass", "seats": 307}`

The desk asks for the "collection reference", i.e. `ref` — submitted verbatim.

## Where I got stuck / notes

- Nothing actually blocked; the only friction was that the template recipe
  didn't apply. Confirms: when a note has prose instead of a timestamp, treat
  the adjectives as the join filters rather than looking for a clock.
- `House 18` / `House18` both 403 — only the `ref` is accepted.

## Reproduce

```
/home/nomad/safaricom_ctf/.venv/bin/python solve.py
```
