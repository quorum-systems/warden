import json
import logging
from pathlib import Path
from typing import Annotated

import pytest
from fastapi import APIRouter, Depends, FastAPI, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import JSONResponse
from fastapi.testclient import TestClient

from warden import trace
from warden.fastapi import ServiceAuth, install
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


# ---- install(): request context and the access line --------------------------------------------------------------

TRACE = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"


def make(tmp_path: Path, guard_router: bool = False) -> tuple[FastAPI, ServiceAuth]:
    f = tmp_path / "keys.json"
    f.write_text(json.dumps([{"name": "marked-words", "sha256": digest(ALL), "grants": "*"}]))
    auth = ServiceAuth("bdl", {"moderations:create"}, f)
    app = FastAPI()
    install(app, service="svc")

    @app.post("/v1/m")
    def create(
        request: Request, who: Annotated[Principal, Depends(auth.require("moderations:create"))]
    ) -> dict[str, str]:
        request.state.outcome = "created"
        seen = trace.current.get()
        return {"trace": seen.trace_id if seen else ""}

    @app.get("/healthz")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    if guard_router:
        router = APIRouter(prefix="/v1/r", dependencies=[Depends(auth.require("moderations:create"))])

        @router.get("/x")
        def x() -> dict[str, str]:
            return {}

        app.include_router(router)
    return app, auth


def lines(caplog: pytest.LogCaptureFixture) -> list[logging.LogRecord]:
    return [r for r in caplog.records if r.name == "svc.access"]


def test_access_line_has_caller_trace_and_route(tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
    app, _ = make(tmp_path)
    c = TestClient(app)
    with caplog.at_level(logging.INFO):
        r = c.post(
            "/v1/m?secret=x", headers={"Authorization": f"Bearer {ALL}", "traceparent": TRACE, "X-Request-Id": "r1"}
        )
        c.get("/healthz")
    assert r.json() == {"trace": "4bf92f3577b34da6a3ce929d0e0e4736"}  # the handler sees the caller's trace
    assert r.headers["x-request-id"] == "r1"
    [line] = lines(caplog)
    got = {
        k: getattr(line, k)
        for k in ("request_id", "trace_id", "parent_span_id", "consumer", "route", "status", "outcome")
    }
    assert got == {
        "request_id": "r1",
        "trace_id": "4bf92f3577b34da6a3ce929d0e0e4736",
        "parent_span_id": "00f067aa0ba902b7",
        "consumer": "marked-words",
        "route": "/v1/m",
        "status": 200,
        "outcome": "created",
    }
    assert "secret" not in repr(line.__dict__)
    assert ALL not in repr(line.__dict__)


def test_access_line_on_auth_failures_and_unknown_paths(tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
    app, _ = make(tmp_path)
    c = TestClient(app)
    with caplog.at_level(logging.INFO):
        c.post("/v1/m")
        c.post("/v1/m", headers={"Authorization": f"Bearer {READ}"})
        c.get("/v1/m/10.1.2.3")
    got = [(r.consumer, r.status, r.outcome, r.route, r.trace_id) for r in lines(caplog)]  # type: ignore[attr-defined]
    assert got == [
        ("unknown", 401, "unauthorized", "/v1/m", None),
        ("unknown", 401, "unauthorized", "/v1/m", None),  # READ isn't in this map
        ("unknown", 404, None, None, None),  # raw path never logged
    ]
    assert "10.1.2.3" not in "".join(
        repr(r.__dict__) for r in lines(caplog)
    )  # httpx (the test client) logs URLs itself


def test_trace_context_does_not_leak_between_requests(tmp_path: Path) -> None:
    app, _ = make(tmp_path)
    c = TestClient(app)
    h = {"Authorization": f"Bearer {ALL}"}
    assert c.post("/v1/m", headers={**h, "traceparent": TRACE}).json()["trace"]
    assert c.post("/v1/m", headers=h).json() == {"trace": ""}
    assert trace.current.get() is None


# ---- enforce(): default deny -------------------------------------------------------------------------------------


def test_enforce_passes_route_and_router_guards(tmp_path: Path) -> None:
    app, auth = make(tmp_path, guard_router=True)
    auth.enforce(app)


def test_enforce_names_unguarded_routes(tmp_path: Path) -> None:
    app, auth = make(tmp_path)

    @app.get("/v1/open")
    def oops() -> dict[str, str]:
        return {}

    @app.get("/v1/status")
    def status() -> dict[str, str]:
        return {}

    with pytest.raises(RuntimeError, match=r"GET /v1/open, GET /v1/status"):
        auth.enforce(app)
    with pytest.raises(RuntimeError, match=r"GET /v1/open$"):
        auth.enforce(app, public=["/v1/status"])


def test_enforce_ignores_another_service_auths_dependency(tmp_path: Path) -> None:
    app, auth = make(tmp_path)
    other = ServiceAuth("bdl", {"moderations:create"}, tmp_path / "keys.json")

    @app.get("/v1/other")
    def guarded_elsewhere(who: Annotated[Principal, Depends(other.require("moderations:create"))]) -> dict[str, str]:
        return {}

    with pytest.raises(RuntimeError, match="/v1/other"):
        auth.enforce(app)


def test_enforce_reports_mounts_plain_routes_and_unguarded_websockets(tmp_path: Path) -> None:
    app, auth = make(tmp_path)
    app.mount("/v1/sub", FastAPI())

    async def raw(_: Request) -> JSONResponse:
        return JSONResponse({})

    app.add_route("/v1/raw", raw)

    @app.websocket("/v1/ws")
    async def ws(websocket: WebSocket) -> None:
        await websocket.accept()

    with pytest.raises(RuntimeError) as e:
        auth.enforce(app)
    for name in ("/v1/sub", "/v1/raw", "/v1/ws"):
        assert name in str(e.value)
    auth.enforce(app, public=["/v1/sub", "/v1/raw", "/v1/ws"])


def test_require_guards_a_websocket(tmp_path: Path) -> None:
    app, auth = make(tmp_path)

    @app.websocket("/v1/ws")
    async def ws(websocket: WebSocket, who: Annotated[Principal, Depends(auth.require("moderations:create"))]) -> None:
        await websocket.accept()
        await websocket.send_json({"name": who.name})
        await websocket.close()

    auth.enforce(app)  # a guarded websocket passes
    c = TestClient(app)
    with c.websocket_connect("/v1/ws", headers={"Authorization": f"Bearer {ALL}"}) as s:
        assert s.receive_json() == {"name": "marked-words"}
    with pytest.raises(WebSocketDisconnect), c.websocket_connect("/v1/ws") as s:
        s.receive_json()


def test_enforce_rejects_a_public_entry_that_matches_nothing(tmp_path: Path) -> None:
    app, auth = make(tmp_path)
    with pytest.raises(RuntimeError, match="public names no route: /v1/stauts"):
        auth.enforce(app, public=["/v1/stauts"])


def test_an_ip_shaped_request_id_is_replaced(tmp_path: Path) -> None:
    app, _ = make(tmp_path)
    c = TestClient(app)
    for rid in ("203.0.113.9", "2001:db8::1"):
        assert c.get("/healthz", headers={"X-Request-Id": rid}).headers["x-request-id"] != rid
