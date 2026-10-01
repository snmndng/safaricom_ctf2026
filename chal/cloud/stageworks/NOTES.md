# Stageworks (CLOUD, 500 pts) — SOLVED

Target: http://54.72.82.22:8400 (Werkzeug/Flask)

Flag: `safctf{b9d2678027feea5870c41931b663fd6d}`

## Recon

Root page lists a "Collection desk" with:
- `GET /downloads/rehearsal.zip`
- `GET /api/identity`
- `POST /api/assume` accepts `role`, `external_id`, `tags`
- `GET /api/object` accepts header `X-Session`

### rehearsal.zip (249 B) contains

`deployment.log`:
```
Lighting integration: externalId=d4a868d5e1dbf4bf89c6c520
```

`policy.json`:
```json
{"trust": {"role": "lighting", "externalId": "integration-value"},
 "object": {"condition": {"sessionTag/department": "finance"}},
 "tagSession": true}
```

This is an AWS STS `AssumeRole` analogue:
- Trust policy: role must be `lighting`, external id must match the deployment log.
- The `object` resource is only readable when the **session tag** `department=finance` is present.
- `tagSession: true` means the tag is passed at assume time and carried by the session.

## Exploit

1. Assume the `lighting` role using the external id leaked in `deployment.log`:
   ```json
   {"role":"lighting","external_id":"d4a868d5e1dbf4bf89c6c520",
    "tags":{"department":"finance"}}
   ```
   -> `{"token":"<36 hex>"}` (session token).

   **Key detail:** `tags` must be a JSON **object/dict** `{"department":"finance"}`, NOT the
   AWS-style list `[{"Key":"department","Value":"finance"}]`. The list form returns a token but
   the session tag is never applied, so the object read fails with HTTP 500 (condition
   evaluation blows up / missing tag). The dict form yields HTTP 200.

2. Use the token on the protected object endpoint:
   ```
   GET /api/object  -H "X-Session: <token>"
   -> {"message":"safctf{b9d2678027feea5870c41931b663fd6d}","ok":true}
   ```

## Misconfiguration summary

Over-permissive trust policy: the external id was leaked in a downloadable deployment archive,
allowing anyone to assume the `lighting` role and, by supplying the required session tag
(`department=finance`, also leaked in the same archive's policy.json), read the protected
S3-style object that holds the flag.

## Status codes observed

- `X-Session: guest` / missing / invalid token -> 403
- valid token WITHOUT session tag (list-form tags) -> 500
- valid token WITH session tag (dict-form tags) -> 200 + flag
