"""Real sops with a throwaway age key, so the CLI is tested on the path the operator uses."""

from __future__ import annotations

import os
import shutil
import subprocess
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

pytestmark = pytest.mark.skipif(shutil.which("sops") is None, reason="needs sops")


@pytest.fixture
def repo(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    key = tmp_path / "age.key"
    subprocess.run(["age-keygen", "-o", str(key)], check=True, capture_output=True)
    public = next(line.split(": ")[1] for line in key.read_text().splitlines() if "public key" in line)
    (tmp_path / ".sops.yaml").write_text(
        "creation_rules:\n- path_regex: service-keys\\.sops\\.yaml$\n"
        f"  encrypted_regex: ^(token|previous)$\n  age: {public}\n"
    )
    monkeypatch.setenv("SOPS_AGE_KEY_FILE", str(key))
    return tmp_path


@pytest.fixture(scope="session")
def vault_dev(tmp_path_factory: pytest.TempPathFactory) -> Iterator[dict[str, str]]:
    """A real `vault server -dev` on a spare port, so VaultCLI is tested against the real CLI's exit codes."""
    if shutil.which("vault") is None:
        pytest.skip("needs the vault binary")
    home = tmp_path_factory.mktemp("vault-home")
    port = 18200 + os.getpid() % 500
    env = os.environ | {"HOME": str(home), "VAULT_ADDR": f"http://127.0.0.1:{port}", "VAULT_TOKEN": "root"}
    proc = subprocess.Popen(
        ["vault", "server", "-dev", "-dev-root-token-id=root", f"-dev-listen-address=127.0.0.1:{port}"],
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    for _ in range(50):
        if subprocess.run(["vault", "status"], check=False, env=env, capture_output=True).returncode == 0:
            break
        time.sleep(0.1)
    else:
        proc.kill()
        pytest.fail("vault dev server didn't start")
    yield env
    proc.kill()
    proc.wait()


class FakeVault:
    def __init__(self) -> None:
        self.data: dict[str, dict[str, Any]] = {}
        self.puts: list[str] = []

    def get(self, path: str) -> dict[str, Any] | None:
        return self.data.get(path)

    def put(self, path: str, data: dict[str, Any]) -> None:
        self.puts.append(path)
        self.data[path] = data

    def list(self, path: str) -> list[str]:
        return sorted({p[len(path) + 1 :].split("/")[0] for p in self.data if p.startswith(path + "/")})

    def delete(self, path: str) -> None:
        del self.data[path]
