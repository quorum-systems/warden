"""install(registry=...): the HTTP and auth series, counted in the middleware so every answer is in them."""

import json
from collections.abc import Callable, Iterable, Sequence
from pathlib import Path
from typing import Annotated

import pytest
from fastapi import Depends, FastAPI, HTTPException, WebSocket
from fastapi.responses import JSONResponse
from fastapi.testclient import TestClient
from prometheus_client import REGISTRY, CollectorRegistry, Counter, generate_latest
from starlette.websockets import WebSocketDisconnect

from warden.fastapi import UNLOGGED, ServiceAuth, install
from warden.keys import Principal, digest
from warden.metrics import AUTH_FAILURES, DEFAULT_BUCKETS, UNMATCHED, Metrics

ALL = "bdl_" + "A" * 43
READ = "bdl_" + "B" * 43
OK = {"Authorization": f"Bearer {ALL}"}


class Harness:
    def __init__(
        self, tmp_path: Path, unlogged: Iterable[str] = UNLOGGED, buckets: Sequence[float] = DEFAULT_BUCKETS
    ) -> None:
        keys = tmp_path / "keys.json"
        keys.write_text(
            json.dumps(
                [
                    {"name": "all", "sha256": digest(ALL), "grants": "*"},
                    {"name": "reader", "sha256": digest(READ), "grants": "moderations:read"},
                ]
            )
        )
        self.registry = CollectorRegistry(auto_describe=True)
        self.auth = ServiceAuth("bdl", {"moderations:create", "moderations:read"}, keys)
        self.app = FastAPI()
        self.metrics: Metrics = install(self.app, "svc", unlogged, registry=self.registry, buckets=buckets)
        guard = Depends(self.auth.require("moderations:create"))

        @self.app.post("/v1/m", dependencies=[guard])
        def create() -> dict[str, str]:
            return {}

        @self.app.get("/v1/m/{item}", dependencies=[guard])
        def read(item: str) -> dict[str, str]:
            return {"item": item}

        @self.app.post("/v1/big", dependencies=[guard])
        def big() -> JSONResponse:
            return JSONResponse({"error": "too_large"}, status_code=413)

        @self.app.post("/v1/refused", dependencies=[guard])
        def refused() -> None:
            raise HTTPException(status_code=413, detail="too large")

        @self.app.post("/v1/boom", dependencies=[guard])
        def boom() -> None:
            raise RuntimeError("handler bug")

        @self.app.get("/healthz")
        def healthz() -> dict[str, str]:
            return {}

        @self.app.get("/metrics")
        def scrape() -> dict[str, str]:
            return {}

        self.client = TestClient(self.app, raise_server_exceptions=False)

    def requests(self, method: str, route: str, code: str) -> float | None:
        return self.registry.get_sample_value(
            "svc_http_requests_total", {"method": method, "route": route, "code": code}
        )

    def failures(self, reason: str) -> float | None:
        return self.registry.get_sample_value("svc_auth_failures_total", {"reason": reason})


@pytest.fixture
def h(tmp_path: Path) -> Harness:
    return Harness(tmp_path)


def test_a_413_returned_by_a_handler_is_counted(h: Harness) -> None:
    assert h.client.post("/v1/big", headers=OK).status_code == 413
    assert h.requests("POST", "/v1/big", "413") == 1


def test_a_413_raised_as_http_exception_is_counted(h: Harness) -> None:
    assert h.client.post("/v1/refused", headers=OK).status_code == 413
    assert h.requests("POST", "/v1/refused", "413") == 1


def test_an_unhandled_exception_is_counted_as_500(h: Harness) -> None:
    assert h.client.post("/v1/boom", headers=OK).status_code == 500
    assert h.requests("POST", "/v1/boom", "500") == 1
    assert h.registry.get_sample_value("svc_http_request_duration_seconds_count", {"route": "/v1/boom"}) == 1


def test_success_carries_the_route_template_not_the_path(h: Harness) -> None:
    h.client.get("/v1/m/10.1.2.3", headers=OK)
    assert h.requests("GET", "/v1/m/{item}", "200") == 1
    assert "10.1.2.3" not in generate_latest(h.registry).decode()


def test_an_unmatched_path_is_one_label_however_many_paths_are_probed(h: Harness) -> None:
    for path in ("/nope", "/v1/also/nope", "/wp-admin/x.php"):
        assert h.client.get(path).status_code == 404
    assert h.requests("GET", UNMATCHED, "404") == 3
    assert "wp-admin" not in generate_latest(h.registry).decode()


def test_a_nonstandard_method_is_one_label_however_many_are_sent(h: Harness) -> None:
    for method in ("PURGE", "PROBE0", "PROBE1"):
        h.client.request(method, "/nope")
    assert h.requests("other", UNMATCHED, "404") == 3
    assert "PROBE" not in generate_latest(h.registry).decode()


def test_unlogged_paths_are_not_counted(h: Harness) -> None:
    for path in ("/healthz", "/metrics"):
        assert h.client.get(path).status_code == 200
    assert h.requests("GET", "/healthz", "200") is None
    assert h.requests("GET", "/metrics", "200") is None
    assert h.registry.get_sample_value("svc_http_request_duration_seconds_count", {"route": "/healthz"}) is None


def test_the_unlogged_list_is_the_installers_to_override(tmp_path: Path) -> None:
    h = Harness(tmp_path, unlogged=frozenset({"/healthz"}))
    h.client.get("/healthz")
    h.client.get("/metrics")
    assert h.requests("GET", "/healthz", "200") is None
    assert h.requests("GET", "/metrics", "200") == 1


@pytest.mark.parametrize(
    ("headers", "reason"),
    [
        ({}, "missing"),
        ({"Authorization": f"Basic {ALL}"}, "missing"),
        ({"Authorization": "Bearer "}, "missing"),
        ({"Authorization": "Bearer bdl_nope"}, "unknown"),
        ({"Authorization": f"Bearer {READ}"}, "forbidden"),
    ],
)
def test_each_refusal_is_counted_under_its_reason(h: Harness, headers: dict[str, str], reason: str) -> None:
    r = h.client.post("/v1/m", headers=headers)
    assert r.status_code == (403 if reason == "forbidden" else 401)
    assert {x: h.failures(x) for x in AUTH_FAILURES} == {x: 1.0 if x == reason else 0.0 for x in AUTH_FAILURES}
    assert h.requests("POST", "/v1/m", str(r.status_code)) == 1  # and it is an ordinary request too


def test_an_accepted_request_is_not_an_auth_failure(h: Harness) -> None:
    h.client.post("/v1/m", headers=OK)
    assert [h.failures(x) for x in AUTH_FAILURES] == [0, 0, 0]


def test_auth_failures_exist_at_zero_before_any_request(h: Harness) -> None:
    text = generate_latest(h.registry).decode()
    for reason in AUTH_FAILURES:
        assert f'svc_auth_failures_total{{reason="{reason}"}} 0.0' in text


def test_seed_routes_creates_the_per_route_series_at_zero(h: Harness) -> None:
    h.app.mount("/v1/sub", FastAPI())

    @h.app.websocket("/v1/ws")
    async def ws(websocket: WebSocket) -> None: ...

    h.metrics.seed_routes(h.app, prefix="/v1", codes=("200", "201"))
    text = generate_latest(h.registry).decode()
    for line in (
        'svc_http_requests_total{code="200",method="POST",route="/v1/m"} 0.0',
        'svc_http_requests_total{code="201",method="POST",route="/v1/m"} 0.0',
        'svc_http_requests_total{code="200",method="GET",route="/v1/m/{item}"} 0.0',
        'svc_http_request_duration_seconds_count{route="/v1/m"} 0.0',
    ):
        assert line in text
    assert "HEAD" not in text
    assert "/healthz" not in text  # outside the prefix
    assert "/v1/ws" not in text  # a websocket has no HTTP method
    h.client.post("/v1/m", headers=OK)
    assert h.requests("POST", "/v1/m", "200") == 1  # seeding does not disturb counting


def test_seed_routes_is_idempotent_and_does_not_reset(h: Harness) -> None:
    h.client.post("/v1/m", headers=OK)
    h.metrics.seed_routes(h.app)
    h.metrics.seed_routes(h.app)
    assert h.requests("POST", "/v1/m", "200") == 1


def test_duration_buckets_are_overridable(tmp_path: Path) -> None:
    h = Harness(tmp_path, buckets=(0.5, 1.0))
    h.client.post("/v1/m", headers=OK)
    text = generate_latest(h.registry).decode()
    assert 'svc_http_request_duration_seconds_bucket{le="0.5",route="/v1/m"} 1.0' in text
    assert 'le="0.005"' not in text


def test_no_registry_means_no_metrics_and_no_change(tmp_path: Path) -> None:
    names = {m.name for m in REGISTRY.collect()}
    app = FastAPI()
    assert install(app, service="svc") is None

    @app.get("/x")
    def x() -> dict[str, str]:
        return {}

    assert TestClient(app).get("/x").status_code == 200
    assert {m.name for m in REGISTRY.collect()} == names  # the process-wide default registry is untouched too


def test_a_second_install_on_one_registry_replaces_the_first(h: Harness) -> None:
    """Tests build the app many times against one module-level registry; the live app's counts are the ones kept."""
    h.client.post("/v1/big", headers=OK)
    app = FastAPI()
    second = install(app, "svc", registry=h.registry)

    @app.get("/v1/y")
    def y() -> dict[str, str]:
        return {}

    TestClient(app).get("/v1/y")
    assert h.requests("POST", "/v1/big", "413") is None
    assert h.requests("GET", "/v1/y", "200") == 1
    assert second is not h.metrics


def test_installs_for_two_services_share_a_registry(h: Harness) -> None:
    install(FastAPI(), "other", registry=h.registry)
    assert h.failures("missing") == 0
    assert h.registry.get_sample_value("other_auth_failures_total", {"reason": "missing"}) == 0


def test_a_service_keeping_its_own_auth_counter_collides() -> None:
    """The adoption trap: bowdler's old `bowdler_auth_failures_total` must be deleted when it passes a registry."""
    registry = CollectorRegistry()
    Counter("svc_auth_failures_total", "old, no labels", registry=registry)
    with pytest.raises(ValueError, match="svc_auth_failures"):
        install(FastAPI(), service="svc", registry=registry)


def test_websocket_refusals_are_not_counted_and_do_not_break(tmp_path: Path) -> None:
    """Documented limit: the middleware is HTTP-only, so a refused websocket handshake never reaches the counter."""
    h = Harness(tmp_path)
    guard: Callable[..., Principal] = h.auth.require("moderations:create")

    @h.app.websocket("/v1/ws")
    async def ws(websocket: WebSocket, who: Annotated[Principal, Depends(guard)]) -> None:
        await websocket.accept()

    with pytest.raises(WebSocketDisconnect), h.client.websocket_connect("/v1/ws"):
        pass
    assert h.failures("missing") == 0
