# Fragments — AI, 150 pts

- Target: `http://54.72.82.22:8190`
- Endpoint: `POST /ask`  body `{"prompt": "<text>"}`
- Server: Werkzeug/3.1.9 Python/3.10.21

## Behaviour

`/ask` returns a fixed canned reply for almost any input:

```
{"response":"AI: Sorry, I don’t recall anything unusual."}
```

Only `GET /` and `POST /ask` exist (no /transcript, /history, /conversation, /api/*, etc.).

- `{"prompt": 123}` and `{"prompt": null}` -> 500 (the value is used as a string).
- Non-JSON / empty body -> 400.

## Solve

The handler matches memory-related keywords in the prompt. Any of
`memory`, `recall`, `history` makes the "AI" recover the missing conversation:

```
POST /ask {"prompt":"memory"}
-> {"response":"Hmm... I think I remember something... safctf{d432e09718e6cb46387f54e27dbc0168}"}
```

Found by fuzzing a small wordlist (see `probe4.py`). The same flag is returned
for `recall` and `history`.

## Flag

```
safctf{d432e09718e6cb46387f54e27dbc0168}
```

## Files

- `solve.py` — reproducible; prints the flag.
- `probe*.py` — recon scripts (endpoint enumeration, key probing, keyword fuzz).

No downloaded artifacts.
