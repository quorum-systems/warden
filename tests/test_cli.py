"""The CLI on a real SOPS file: tokens encrypted at rest, names and grants readable, edits round-trip."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml
from conftest import FakeVault

from warden import cli, sops, sync
from warden.keys import HashMap, KeysFile, digest


def file(repo: Path) -> Path:
    f = repo / "service-keys.sops.yaml"
    cli.main(
        ["init", str(f), "--service", "bowdler", "--prefix", "bdl", "--grants", "moderations:create,moderations:read"]
    )
    return f


def test_issue_encrypts_token_only(repo: Path) -> None:
    f = file(repo)
    cli.main(["issue", str(f), "marked-words", "--grants", "*"])
    raw = yaml.safe_load(f.read_text())
    assert raw["keys"][0]["name"] == "marked-words"
    assert raw["keys"][0]["grants"] == "*"
    assert raw["keys"][0]["token"].startswith("ENC[")
    kf = KeysFile.parse(sops.decrypt(f))
    assert kf.keys[0].token.startswith("bdl_")
    assert len(kf.keys[0].token) == 4 + 43


def test_list_masks_unless_show(repo: Path, capsys: pytest.CaptureFixture[str]) -> None:
    f = file(repo)
    cli.main(["issue", str(f), "marked-words", "--grants", "moderations:create"])
    token = KeysFile.parse(sops.decrypt(f)).keys[0].token
    capsys.readouterr()
    cli.main(["list", str(f)])
    out = capsys.readouterr().out
    assert "marked-words" in out
    assert "moderations:create" in out
    assert token not in out
    cli.main(["list", str(f), "--show"])
    assert token in capsys.readouterr().out


def test_rotation_keeps_previous_until_retired(repo: Path) -> None:
    f = file(repo)
    cli.main(["issue", str(f), "mw", "--grants", "*"])
    old = KeysFile.parse(sops.decrypt(f)).keys[0].token
    with pytest.raises(SystemExit, match="--rotate"):
        cli.main(["issue", str(f), "mw", "--grants", "*"])
    cli.main(["issue", str(f), "mw", "--grants", "*", "--rotate"])
    k = KeysFile.parse(sops.decrypt(f)).keys[0]
    assert k.token != old
    assert k.previous == old
    assert yaml.safe_load(f.read_text())["keys"][0]["previous"].startswith("ENC[")
    assert len(KeysFile.parse(sops.decrypt(f)).hash_map()) == 2
    with pytest.raises(SystemExit, match="mid-rotation"):
        cli.main(["issue", str(f), "mw", "--grants", "*", "--rotate"])
    cli.main(["retire", str(f), "mw"])
    k = KeysFile.parse(sops.decrypt(f)).keys[0]
    assert k.previous is None
    assert len(KeysFile.parse(sops.decrypt(f)).hash_map()) == 1


def test_refuses_a_rule_that_leaves_tokens_plaintext(repo: Path) -> None:
    rules = (repo / ".sops.yaml").read_text().replace("^(token|previous)$", "^(data|stringData)$")
    (repo / ".sops.yaml").write_text(rules)
    f = repo / "service-keys.sops.yaml"
    with pytest.raises(SystemExit, match="doesn't encrypt"):
        cli.main(["init", str(f), "--service", "bowdler", "--prefix", "bdl", "--grants", "moderations:create"])
    assert not f.exists()


def test_undeclared_grant_rejected_at_issue(repo: Path) -> None:
    f = file(repo)
    with pytest.raises(SystemExit, match="not declared"):
        cli.main(["issue", str(f), "a", "--grants", "x:read"])


def test_declare(repo: Path) -> None:
    f = file(repo)
    cli.main(["issue", str(f), "a", "--grants", "moderations:read"])
    with pytest.raises(SystemExit, match="not declared"):
        cli.main(["declare", str(f), "--grants", "moderations:create"])
    cli.main(["declare", str(f), "--grants", "moderations:read,moderations:delete"])
    assert KeysFile.parse(sops.decrypt(f)).grants == {"moderations:read", "moderations:delete"}


def test_grants_and_revoke(repo: Path) -> None:
    f = file(repo)
    cli.main(["issue", str(f), "a", "--grants", "*"])
    cli.main(["issue", str(f), "b", "--grants", "*"])
    cli.main(["grants", str(f), "a", "--grants", "moderations:read"])
    cli.main(["revoke", str(f), "b"])
    kf = KeysFile.parse(sops.decrypt(f))
    assert [(k.name, k.grants) for k in kf.keys] == [("a", "moderations:read")]


def test_bad_grants_rejected(repo: Path) -> None:
    f = file(repo)
    with pytest.raises(SystemExit, match="grant"):
        cli.main(["issue", str(f), "a", "--grants", "everything"])


def test_sync_plan_apply_prune(repo: Path) -> None:
    f = file(repo)
    cli.main(["issue", str(f), "a", "--grants", "*"])
    cli.main(["issue", str(f), "b", "--grants", "*"])
    kf = KeysFile.parse(sops.decrypt(f))
    v = FakeVault()
    v.data["k8s/services/bowdler/consumers/gone"] = {"token": "bdl_x"}
    p = sync.plan(kf, v)
    assert set(p.writes) == {
        "k8s/services/bowdler/keys",
        "k8s/services/bowdler/consumers/a",
        "k8s/services/bowdler/consumers/b",
    }
    assert p.stale == ["k8s/services/bowdler/consumers/gone"]
    assert all("bdl_" not in line for line in p.lines())
    sync.apply(p, v, prune=False)
    assert "k8s/services/bowdler/consumers/gone" in v.data
    p = sync.plan(kf, v)
    assert not p.writes
    sync.apply(p, v, prune=True)
    assert "k8s/services/bowdler/consumers/gone" not in v.data
    hm = HashMap.from_json("bdl", v.data["k8s/services/bowdler/keys"]["keys.json"], frozenset({"moderations:create"}))
    assert hm.names == {"a", "b"}
    assert v.puts[0] == "k8s/services/bowdler/keys"  # the service learns a hash before the consumer gets the token
    assert v.data["k8s/services/bowdler/consumers/a"]["token"] == kf.keys[0].token
    assert digest(kf.keys[0].token) in v.data["k8s/services/bowdler/keys"]["keys.json"]
