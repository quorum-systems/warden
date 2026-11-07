# warden

Per-consumer API keys for Quorum services, one process for all of them: a grant model, a FastAPI dependency, and a CLI that manages a service's keys in a SOPS file and syncs them to Vault for External Secrets.

## Model

* **Keys file**, the source of truth, in quorum/platform: `gitops/secrets/<group>/<service>/keys/service-keys.sops.yaml`. The `keys/` subdirectory matters: Argo CD's `sops-decrypt` plugin outputs every `*.sops.yaml` at the top of an app's directory as a manifest, so a keys file beside a service's Secrets would put plaintext tokens in rendered manifests. It holds the service's declared `grants` and one entry per consumer: `name`, `token`, `grants`, and `previous` during a rotation. Only `token` and `previous` are encrypted, so names and grants read in diffs. That needs this rule in platform's `.sops.yaml`, **above** the generic `gitops/secrets/` rule (sops uses the first match). warden refuses to write if the matching rule wouldn't encrypt tokens:

  ```yaml
  - path_regex: ^gitops/secrets/.*/service-keys\.sops\.yaml$
    encrypted_regex: ^(token|previous)$
    age: <the platform recipients>
  ```
* **Grants** are `<resource>:<action>`: a lowercase plural noun, and an action from `read`, `create`, `update`, `delete`, `admin` (`moderations:create`, `locations:read`). Each service declares the grants it checks, in code and in its keys file (`warden declare`). A key holds `*` (every declared grant) or a comma-separated list, and the CLI rejects grants the file doesn't declare. The service also refuses to start if its key map names a grant its code doesn't declare, so keep the two lists equal.
* **Tokens** are `<prefix>_` plus 256 random bits in base64url (`bdl_…`, `mct_…`).
* **Vault** (KV v2, mount `secret`, under the `k8s/` path ESO's policy reads):
  * `k8s/services/<service>/keys`: `{"keys.json": …}`, name, SHA-256 and grants per key. The service's ExternalSecret mounts it. Hashes only.
  * `k8s/services/<service>/consumers/<name>`: `{"token": …}`. That consumer's ExternalSecret reads only its own.

## CLI

```bash
warden init    gitops/secrets/ai/bowdler/keys/service-keys.sops.yaml --service bowdler --prefix bdl --grants moderations:create
warden declare <file> --grants moderations:create,moderations:read
warden issue   <file> marked-words --grants '*'
warden issue   <file> marked-words --grants '*' --rotate   # old token stays accepted as `previous`
warden retire  <file> marked-words                          # once the consumer runs the new token
warden grants  <file> marked-words --grants moderations:create
warden revoke  <file> marked-words
warden list    <file> [--show]
warden sync    <file> [--apply] [--prune]
```

Every edit goes through `sops set`/`unset` with values on stdin. Nothing is written decrypted and tokens never reach argv. `list` masks tokens unless you pass `--show`. `sync` prints a plan of paths only and writes nothing without `--apply`. It writes the service's hash map before consumer tokens, so a service never rejects a token its consumer already has, and `--prune` deletes consumers no longer in the file. It needs `VAULT_ADDR` and a `vault login` session. A Vault error (403, bad token, unreachable) fails the command; only a genuinely missing path reads as empty. Revoking the last key leaves an empty map: the service starts and answers 401 to everyone.

## The service standard

One library for both ends of every internal call. Install the extra for the side you are:

* `warden[server]`: a FastAPI service. `ServiceAuth`, `install`, `enforce`.
* `warden[client]`: anything that calls a Quorum service. `WardenAuth` for httpx. It never pulls in FastAPI.
* The bare package: grants, keys, trace context, and the `warden` CLI (needs `sops` and `vault` on PATH).

### Server

```python
from warden.fastapi import ServiceAuth, install
from warden.keys import Principal

auth = ServiceAuth(prefix="bdl", grants={"moderations:create"}, keys_file=Path(os.environ["BOWDLER_API_KEYS_FILE"]))
install(app, service="bowdler")


@app.post("/v1/moderations")
def moderate(req: ModerationRequest, who: Annotated[Principal, Depends(auth.require("moderations:create"))]): ...


# A whole router: APIRouter(prefix="/v1/admin", dependencies=[Depends(auth.require("moderations:admin"))])

auth.enforce(app, prefix="/v1")  # last, after every route: refuses to start if a /v1 route has no warden dependency
```

* **Auth runs at FastAPI's dependency stage**, per route or per router, so the grant shows in OpenAPI and tests can override it. A missing, malformed or unknown key is a 401 with `detail="unauthorized"`. A known key without the grant is a 403 with `detail="forbidden"`. The service's exception handler shapes the body.
* **`install(app, service=...)`** adds one middleware. It takes `X-Request-Id` (1 to 128 of `[A-Za-z0-9_-]`) or generates one and echoes it back. It reads the caller's W3C `traceparent` into `warden.trace.current`; an invalid header is ignored, never repaired. It writes one INFO line per request on logger `<service>.access`: `request_id`, `trace_id`, `parent_span_id`, `consumer` (the key's name, or `unknown`), `method`, `route` (the template, never the raw path or query), `status`, `outcome`, `duration_ms`. A handler can set `request.state.outcome` to a short bounded word. `/healthz`, `/readyz`, `/livez` and `/metrics` aren't logged.
* **`enforce`** is default-deny over every kind of route under the prefix: a mount, a plain Starlette route or a websocket without a warden dependency fails startup too. Name deliberately open paths with `public=["/v1/status"]`; an entry that matches no route is an error. Routes registered after `enforce` aren't checked, so call it last.
* **Streaming responses:** the access line is written when the response headers are ready, so for a streamed body `duration_ms` is time to first byte, and an error mid-stream still logs the status already sent. Fix before a streaming service adopts it (a plain ASGI middleware).

### Client

```python
import httpx
from warden.client import WardenAuth

mercator = httpx.Client(base_url="http://mercator.mercator.svc:8080", auth=WardenAuth.from_env("MERCATOR"))
```

* The key comes from `MERCATOR_API_KEY_FILE` (the ExternalSecret mount; preferred) or `MERCATOR_API_KEY`. A file is re-read when it changes, so a rotated key lands without a restart. Mount the Secret as a volume, not with `subPath`: a subPath mount never sees updates. Missing or empty fails at construction, not on the first call; if the file disappears later, each call raises with the path (never the key) in the message.
* `X-Request-Id` isn't forwarded, and a call that started without a `traceparent` (a cron job, a worker) has no trace id to pass on. Start one at the edge if you need those linked.
* Every request gets `Authorization: Bearer <key>` and, inside a request served under `install`, the caller's `traceparent`, so the next service's access line carries the same trace id. Headers you set explicitly win.
* Works with `httpx.Client` and `httpx.AsyncClient`.

A service that runs an OpenTelemetry SDK creates its own spans and propagates through it. `warden.trace` is the floor that every service gets regardless.

## Install

Published to the Gitea PyPI registry on a `v*` tag:

```toml
[[tool.uv.index]]
name = "quorum"
url = "https://gitea.ops.quorumsystems.io/api/packages/quorum-actions/pypi/simple"
explicit = true

[tool.uv.sources]
warden = { index = "quorum" }
```

## Rotation

1. `warden issue <file> <name> --grants … --rotate`, then `warden sync --apply`. The service now accepts both tokens, and the consumer's ExternalSecret hands it the new one.
2. Once the consumer runs the new token (its pods rolled), `warden retire <file> <name>` and sync again.
