# warden

Per-consumer API keys for Quorum services, one process for all of them: a grant model, a FastAPI dependency, and a CLI that manages a service's keys in a SOPS file and syncs them to Vault for External Secrets.

## Model

* **Keys file**, the source of truth, in quorum/platform: `gitops/secrets/<group>/<service>/service-keys.sops.yaml`. It holds the service's declared `grants` and one entry per consumer: `name`, `token`, `grants`, and `previous` during a rotation. Only `token` and `previous` are encrypted, so names and grants read in diffs. That needs this rule in platform's `.sops.yaml`, **above** the generic `gitops/secrets/` rule (sops uses the first match). warden refuses to write if the matching rule wouldn't encrypt tokens:

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
warden init    gitops/secrets/ai/bowdler/service-keys.sops.yaml --service bowdler --prefix bdl --grants moderations:create
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

## FastAPI

```python
from warden.fastapi import ServiceAuth
from warden.keys import Principal

auth = ServiceAuth(prefix="bdl", grants={"moderations:create"}, keys_file=Path(os.environ["BOWDLER_API_KEYS_FILE"]))


@app.post("/v1/moderations")
def moderate(req: ModerationRequest, who: Annotated[Principal, Depends(auth.require("moderations:create"))]): ...
```

A missing, malformed or unknown key is a 401 with `detail="unauthorized"`. A known key without the grant is a 403 with `detail="forbidden"`. The service's exception handler shapes the body.

## Install

Published to the Gitea PyPI registry on a `v*` tag:

```toml
[[tool.uv.index]]
name = "quorum"
url = "https://gitea.ops.quorumsystems.io/api/packages/quorum/pypi/simple"
explicit = true

[tool.uv.sources]
warden = { index = "quorum" }
```

## Rotation

1. `warden issue <file> <name> --grants … --rotate`, then `warden sync --apply`. The service now accepts both tokens, and the consumer's ExternalSecret hands it the new one.
2. Once the consumer runs the new token (its pods rolled), `warden retire <file> <name>` and sync again.
