"""Vault KV v2 through the `vault` CLI (VAULT_ADDR and a token from `vault login`). Values travel on stdin/stdout."""

from __future__ import annotations

import json
import subprocess
from typing import Any, Protocol


class Store(Protocol):
    def get(self, path: str) -> dict[str, Any] | None: ...
    def put(self, path: str, data: dict[str, Any]) -> None: ...
    def list(self, path: str) -> list[str]: ...
    def delete(self, path: str) -> None: ...


class VaultCLI:
    def __init__(self, mount: str = "secret") -> None:
        self.mount = mount

    def _run(self, *args: str, stdin: bytes | None = None) -> subprocess.CompletedProcess[bytes]:
        return subprocess.run(["vault", *args], input=stdin, capture_output=True, check=False)

    def get(self, path: str) -> dict[str, Any] | None:
        r = self._run("kv", "get", f"-mount={self.mount}", "-format=json", path)
        # rc 2 covers both "missing" and remote errors (403, bad token, unreachable); only the message tells them apart.
        if r.returncode == 2 and r.stderr.startswith(b"No value found at"):
            return None
        _check(r)
        data: dict[str, Any] = json.loads(r.stdout)["data"]["data"]
        return data

    def put(self, path: str, data: dict[str, Any]) -> None:
        _check(self._run("kv", "put", f"-mount={self.mount}", path, "-", stdin=json.dumps(data).encode()))

    def list(self, path: str) -> list[str]:
        r = self._run("kv", "list", f"-mount={self.mount}", "-format=json", path)
        if r.returncode == 2 and r.stdout.strip() == b"{}":  # nothing under this path
            return []
        _check(r)
        return [str(x).rstrip("/") for x in json.loads(r.stdout)]

    def delete(self, path: str) -> None:
        _check(self._run("kv", "metadata", "delete", f"-mount={self.mount}", path))


class VaultError(RuntimeError):
    pass


def _check(r: subprocess.CompletedProcess[bytes]) -> None:
    """Raise with vault's own message. Only stderr: stdout of a `kv get` holds secret values."""
    if r.returncode != 0:
        raise VaultError(f"vault {' '.join(map(str, r.args[1:3]))} failed: {r.stderr.decode(errors='replace').strip()}")
