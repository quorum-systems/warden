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

* `warden[server]`: a FastAPI service. `ServiceAuth`, `install`, `enforce`, and the HTTP/auth metrics (adds `prometheus-client`).
* `warden[client]`: anything that calls a Quorum service. `WardenAuth` for httpx. It never pulls in FastAPI.
* The bare package: grants, keys, trace context, and the `warden` CLI (needs `sops` and `vault` on PATH).

### Server

```python
from warden.fastapi import ServiceAuth, install
from warden.keys import Principal

auth = ServiceAuth(prefix="bdl", grants={"moderations:create"}, keys_file=Path(os.environ["BOWDLER_API_KEYS_FILE"]))
metrics = install(app, service="bowdler", registry=REGISTRY)  # registry is optional; omit it for no metrics


@app.post("/v1/moderations")
def moderate(req: ModerationRequest, who: Annotated[Principal, Depends(auth.require("moderations:create"))]): ...


# A whole router: APIRouter(prefix="/v1/admin", dependencies=[Depends(auth.require("moderations:admin"))])

auth.enforce(app, prefix="/v1")  # last, after every route: refuses to start if a /v1 route has no warden dependency
metrics.seed_routes(app, prefix="/v1")  # zero-init the per-route request series (see Metrics)
```

* **Auth runs at FastAPI's dependency stage**, per route or per router, so the grant shows in OpenAPI and tests can override it. A missing, malformed or unknown key is a 401 with `detail="unauthorized"`. A known key without the grant is a 403 with `detail="forbidden"`. The service's exception handler shapes the body.
* **`install(app, service=...)`** adds one middleware. It takes `X-Request-Id` (1 to 128 of `[A-Za-z0-9_-]`) or generates one and echoes it back. It reads the caller's W3C `traceparent` into `warden.trace.current`; an invalid header is ignored, never repaired. It writes one INFO line per request on logger `<service>.access`: `request_id`, `trace_id`, `parent_span_id`, `consumer` (the key's name, or `unknown`), `method`, `route` (the template, never the raw path or query), `status`, `outcome`, `duration_ms`. A handler can set `request.state.outcome` to a short bounded word. `/healthz`, `/readyz`, `/livez` and `/metrics` aren't logged.
* **`enforce`** is default-deny over every kind of route under the prefix: a mount, a plain Starlette route or a websocket without a warden dependency fails startup too. Name deliberately open paths with `public=["/v1/status"]`; an entry that matches no route is an error. Routes registered after `enforce` aren't checked, so call it last.
* **Streaming responses:** the access line is written when the response headers are ready, so for a streamed body `duration_ms` is time to first byte, and an error mid-stream still logs the status already sent. Fix before a streaming service adopts it (a plain ASGI middleware).

### Metrics

`install(app, service, unlogged=UNLOGGED, registry=None, buckets=DEFAULT_BUCKETS)` records three series when you pass a prometheus_client `CollectorRegistry` (the service's own, the one it serves on `/metrics`). With `registry=None` nothing is imported, registered or recorded, exactly as in 0.1.x. All names are prefixed with `service`; the service's own domain metrics stay as they are.

| Series | Labels | Counts |
| --- | --- | --- |
| `<service>_http_requests_total` | `method`, `route`, `code` | every request except the `unlogged` paths (`/healthz`, `/readyz`, `/livez`, `/metrics`) |
| `<service>_http_request_duration_seconds` | `route` | wall time through the whole stack, same exclusions; default buckets 5 ms to 10 s |
| `<service>_auth_failures_total` | `reason` | `missing` (no bearer credential), `unknown` (no key matches), `forbidden` (key lacks the grant) |

* **Counted in the middleware, not in handlers.** A 413 from a body-size limit or a handler's `raise`, a 404, and an unhandled exception (counted as `500`) all land in `http_requests_total`, which per-handler counting can't see. The access line and the metrics are written in the same `finally`.
* **`route` is bounded.** It is the matched route template (`/v1/moderations`, `/v1/m/{item}`), or the literal `unmatched` when nothing matched, so probing `/wp-admin/x.php` adds no series. `code` is the numeric status as a string.
* **Zero-init.** A Prometheus counter does not exist until its first increment, so `rate()` over a series that never fired returns nothing, `increase()` drops the first event after a restart, and `absent()` alerts fire on a healthy service. `auth_failures_total` is created at 0 for its three reasons at install. `metrics.seed_routes(app, prefix="/v1", codes=("200",))` does the same for `(method, route, code)` of every HTTP route under the prefix (pass `("201",)` for a create route, or several); call it after the routes are registered, next to `enforce`. Other codes (4xx, 5xx) are not knowable up front and appear on first use, so alert on error ratios, never on `absent()` of a rare code.
* **Auth failures are read off the request**: `ServiceAuth` notes the reason on `request.state` and the middleware counts it, so there is nothing to wire between the two. It covers HTTP routes only: a websocket never passes through the middleware.
* **Adopting**: pass a registry that does not already hold these names. `install` raises `ValueError` on a duplicate, so a service's own `<service>_auth_failures_total` must be deleted first. `_created` series are a process-wide switch (`prometheus_client.disable_created_metrics()`) that warden leaves to the service.

### Testing

`warden.testing` is a pytest plugin, registered by entry point: it loads wherever warden and pytest are installed, needs no conftest line, and does nothing until a `debt.yaml` is collected. pytest itself is the service's own dependency.

```python
# tests/test_docs.py
from pathlib import Path
from warden.testing import check_docs
from bowdler.metrics import REGISTRY


def test_readme_matches_the_service() -> None:
    check_docs(Path(__file__).resolve().parent.parent, package="bowdler", env_prefix="BOWDLER_", metrics=REGISTRY)


# tests/test_auth.py
from warden.testing import assert_routes_guarded


def test_every_v1_route_has_a_key_check(app) -> None:
    assert_routes_guarded(app, prefix="/v1", public=[])
```

* **Debt ratchet.** Keep the gaps against the testing standard in `tests/debt.yaml`; pytest collects it as `debt.yaml::_schema` plus one item per entry id, so there is no `test_debt.py` to copy. Each entry has `id`, `gap`, `owner`, `since`, `exit` and exactly one of `open_when` (a Python expression with `ROOT`, the directory above `tests/`, and `Path` in scope; the entry fails with "delete it" once it turns false) or `review_by` (a YAML date; the entry fails after it until fixed or re-reviewed). `check_debt(path)` runs the same checks inside a test of your own.
* **`check_docs(root, package, env_prefix, metrics)`**: the README (at `root/README.md`) names every `<env_prefix>*` variable under `src/<package>` in backticks, names every metric family (`name`, `name_total` or `name_info`, followed by a backtick or `{`), and names no `<package>_*` metric that isn't exported. `metrics` is a CollectorRegistry (pass it after `install`, so warden's series are checked too) or a module of collectors. Findings are reported together.
* **`assert_routes_guarded(app, prefix="/v1", public=())`**: the logic of `enforce`, for a test against the built app. Any warden guard satisfies it (a test has no `ServiceAuth` instance; `enforce` still checks against its own), and it fails if nothing lives under the prefix or a `public` entry matches no route.

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
