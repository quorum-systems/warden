"""VaultCLI against a real dev server: exit codes for missing paths and for real errors differ only in the message."""

from __future__ import annotations

import pytest

from warden.vault import VaultCLI, VaultError


@pytest.fixture
def vault(vault_dev: dict[str, str], monkeypatch: pytest.MonkeyPatch) -> VaultCLI:
    for k, val in vault_dev.items():
        monkeypatch.setenv(k, val)
    return VaultCLI("secret")


def test_missing_reads_as_empty(vault: VaultCLI) -> None:
    assert vault.get("k8s/services/nope/keys") is None
    assert vault.list("k8s/services/nope/consumers") == []


def test_round_trip_and_delete(vault: VaultCLI) -> None:
    vault.put("k8s/services/t/consumers/a", {"token": "bdl_x"})
    assert vault.get("k8s/services/t/consumers/a") == {"token": "bdl_x"}
    assert vault.list("k8s/services/t/consumers") == ["a"]
    vault.delete("k8s/services/t/consumers/a")
    assert vault.get("k8s/services/t/consumers/a") is None
    assert vault.list("k8s/services/t/consumers") == []


def test_errors_are_not_mistaken_for_missing(vault: VaultCLI, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("VAULT_TOKEN", "not-a-token")
    with pytest.raises(VaultError, match="failed"):
        vault.get("k8s/services/t/keys")
    with pytest.raises(VaultError, match="failed"):
        vault.list("k8s/services/t/consumers")
    monkeypatch.setenv("VAULT_ADDR", "http://127.0.0.1:1")
    with pytest.raises(VaultError):
        vault.get("k8s/services/t/keys")
