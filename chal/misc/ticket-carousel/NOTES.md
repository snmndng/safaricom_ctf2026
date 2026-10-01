# Ticket Carousel — desk app, :8630 (unlisted; CARNIVAL theme)

Target: `http://54.72.82.22:8630` (Werkzeug 3.1.9 / Python 3.11.16)
Flag: `safctf{5b701cd93c298559638b8b4181bfa5e2}`

## What it is

A 40-state deterministic automaton, handed to you in the open. The desk page
links `/downloads/carousel.map`:

```json
{"initial": 0, "closing": 39,
 "table": {"0": {"A": 4, "B": 31, "C": 21, "D": 27}, ... "39": {...}}}
```

API (both JSON in, JSON out):

| Call | Effect |
| --- | --- |
| `POST /api/round` | mints a round: `{"round":"1c503c63d10572d9"}` (16 hex) |
| `POST /api/move {"round","symbol"}` | steps the automaton, returns `{"position": n}` |

An unknown/missing symbol is ignored (you stay at the current position), so
there is no injection surface here — the puzzle is purely "walk the map".

## Solve

BFS `initial -> closing` gives the 3-move path **`DAB`**:

```
0 -D-> 27 -A-> 36 -B-> 39   (closing)
```

Replaying it against a live round ends the round and hands over the flag:

```
move D -> {"position":27}
move A -> {"position":36}
move B -> {"message":"Round complete: safctf{5b701cd93c298559638b8b4181bfa5e2}","ok":true}
```

For completeness the map has one state — **14** — that is unreachable from
`initial`; it is a decoy, not part of the solve.

## Reproduce

```bash
python3 solve.py [base_url]     # stdlib only
```

## Side finding: `/submit` 403 is not a WAF

Every desk app (8450, 8630, 8640, …) answers `POST /submit` with

```
403 {"message":"The request could not be completed.","ok":false}
```

which reads exactly like the platform's WAF rejection seen on the WEB ports. It
is **not** a WAF — it is these apps' generic *wrong-answer* response.
Submitting a correct answer returns

```
200 {"message":"<the real safctf flag>","ok":true}
```

Confirmed on 8450 (Matchday Replay) with its known answer. This matters for
triage: a 403 from `/submit` means "not the answer yet", and should not be
recorded as a block.
