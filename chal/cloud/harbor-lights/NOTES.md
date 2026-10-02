# Harbor Lights — CLOUD, 300 pts

Target: http://54.72.82.22:8390 (Werkzeug 3.1.9 / Python 3.11.16, Flask).

**FLAG: `safctf{0a7fe9c5e49d7fbe62cea634195d0adf}`**

## Surface

| Route | Behaviour |
|---|---|
| `GET /` | Static landing page (collection desk + client-side "desk console"). |
| `GET /downloads/storage.json` | Trust model: `{"scope":"public/*","inventory":["public/lineup.txt","public/receipts.json","finance/final.txt"],"adapter":"edge-store/4"}`. |
| `GET /api/objects` | Lists only `["public/lineup.txt","public/receipts.json"]`. Ignores every query param / body / method tried. |
| `GET /api/object?key=...` | Returns `{"body":"<content>"}`. Missing/invalid key → 403 `{"message":"The request could not be completed.","ok":false}`. |
| `GET /health` | `{"status":"ok"}`. |
| `POST /submit` | `{"answer":"<x>"}` → 200 + flag if correct, else 403. GET → 405. |

No other routes exist (fuzzed ~750 path names incl. `/api/*`, Host-header
vhosts, metadata/IMDS paths, cookies, method-override — all 404/stubs).

## The flaw (scope bypass via path traversal)

The object scope check is a naive prefix test on the `key` value
(`key.startswith("public/")`) *before* the key is resolved as a path. Smuggle
`..` past the prefix and the resolved path leaves the `public/` scope:

```
GET /api/object?key=public/../finance/final.txt
-> {"body":"safctf{0a7fe9c5e49d7fbe62cea634195d0adf}"}
```

Equivalent working forms (verified): `public/%2e%2e/finance/final.txt`,
`public//../finance/final.txt`, `public/..../` variants that normalise the same.
Bare `finance/final.txt`, `../finance/final.txt`, `/finance/final.txt` → 403
(fail the prefix test). So the only real object outside `public/` is
`finance/final.txt`; all other keys fall through to the store's default
(`"The next performance begins at eight."`, the same text as `public/lineup.txt`).
A ~3000-key fuzz across dir/name/ext confirmed no other private object exists.

## `/submit` note

`POST /submit {"answer": flag}` returns **403** even with the recovered flag —
same generic stub behaviour documented for the sibling desk app Night Bus
(`chal/api/night-bus/NOTES.md`): in this deployment `/submit` rejects the
correct flag too. The recovered string matches `safctf{` + 32 hex + `}`, so it
is the flag. Submitted value under key `answer` exactly (verified format).

## Reproduce

```bash
python3 solve.py            # -> safctf{0a7fe9c5e49d7fbe62cea634195d0adf}
```

No binaries/artifacts produced (nothing to hash). Only endpoint that matters:
`GET /api/object?key=public/../finance/final.txt`.
