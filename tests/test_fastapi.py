import json
from pathlib import Path
from typing import Annotated

import pytest
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

from warden.fastapi import ServiceAuth
from warden.keys import Principal, digest

ALL = "bdl_" + "A" * 43
READ = "bdl_" + "B" * 43


@pytest.fixture
def client(tmp_path: Path) -> TestClient:
    f = tmp_path / "keys.json"
    f.write_text(
        json.dumps(
            [
                {"name": "all", "sha256": digest(ALL), "grants": "*"},
                {"name": "reader", "sha256": digest(READ), "grants": "moderations:read"},
            ]
        )
    )
    auth = ServiceAuth("bdl", {"moderations:create", "moderations:read"}, f)
    app = FastAPI()

    @app.post("/m")
    def create(who: Annotated[Principal, Depends(auth.require("moderations:create"))]) -> dict[str, str]:
        return {"name": who.name}

    return TestClient(app)


def test_allowed(client: TestClient) -> None:
    r = client.post("/m", headers={"Authorization": f"bearer {ALL}"})
    assert (r.status_code, r.json()) == (200, {"name": "all"})


@pytest.mark.parametrize("header", [None, "Bearer bdl_nope", f"Basic {ALL}", "Bearer mct_" + "A" * 43])
def test_unauthorized(client: TestClient, header: str | None) -> None:
    r = client.post("/m", headers={"Authorization": header} if header else {})
    assert r.status_code == 401


def test_forbidden_without_grant(client: TestClient) -> None:
    assert client.post("/m", headers={"Authorization": f"Bearer {READ}"}).status_code == 403


def test_undeclared_grant_in_map_fails_startup(tmp_path: Path) -> None:
    f = tmp_path / "keys.json"
    f.write_text(json.dumps([{"name": "x", "sha256": digest(ALL), "grants": "locations:read"}]))
    with pytest.raises(ValueError, match="not declared"):
        ServiceAuth("bdl", {"moderations:create"}, f)


def test_require_undeclared_grant_is_a_bug(tmp_path: Path) -> None:
    f = tmp_path / "keys.json"
    f.write_text(json.dumps([{"name": "x", "sha256": digest(ALL), "grants": "*"}]))
    with pytest.raises(ValueError, match="declared"):
        ServiceAuth("bdl", {"moderations:create"}, f).require("moderations:delete")


def test_empty_map_starts_and_rejects(tmp_path: Path) -> None:
    f = tmp_path / "keys.json"
    f.write_text("[]")
    auth = ServiceAuth("bdl", {"moderations:create"}, f)
    app = FastAPI()

    @app.post("/m")
    def create(who: Annotated[Principal, Depends(auth.require("moderations:create"))]) -> dict[str, str]:
        return {"name": who.name}

    assert TestClient(app).post("/m", headers={"Authorization": f"Bearer {ALL}"}).status_code == 401
