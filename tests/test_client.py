import asyncio
import os
from pathlib import Path

import httpx
import pytest

from warden import trace
from warden.client import WardenAuth

KEY = "mct_" + "A" * 43
CTX = trace.TraceContext("4bf92f3577b34da6a3ce929d0e0e4736", "00f067aa0ba902b7", "01")


def echo(request: httpx.Request) -> httpx.Response:
    return httpx.Response(
        200, json={"auth": request.headers.get("authorization"), "tp": request.headers.get("traceparent")}
    )


def client(auth: WardenAuth) -> httpx.Client:
    return httpx.Client(transport=httpx.MockTransport(echo), auth=auth, base_url="http://svc")


def test_sends_the_key_and_no_trace_outside_a_request() -> None:
    assert client(WardenAuth(KEY)).get("/").json() == {"auth": f"Bearer {KEY}", "tp": None}


def test_forwards_the_current_trace() -> None:
    token = trace.current.set(CTX)
    try:
        assert client(WardenAuth(KEY)).get("/").json()["tp"] == CTX.traceparent
    finally:
        trace.current.reset(token)


def test_explicit_headers_win() -> None:
    token = trace.current.set(CTX)
    try:
        r = client(WardenAuth(KEY)).get("/", headers={"Authorization": "Bearer other", "traceparent": "x"})
    finally:
        trace.current.reset(token)
    assert r.json() == {"auth": "Bearer other", "tp": "x"}


def test_async_client() -> None:
    async def go() -> dict[str, str]:
        token = trace.current.set(CTX)
        try:
            async with httpx.AsyncClient(transport=httpx.MockTransport(echo), auth=WardenAuth(KEY)) as c:
                return (await c.get("http://svc/")).json()  # type: ignore[no-any-return]
        finally:
            trace.current.reset(token)

    assert asyncio.run(go()) == {"auth": f"Bearer {KEY}", "tp": CTX.traceparent}


def test_from_env_prefers_the_file_and_rereads_it_on_rotation(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    f = tmp_path / "key"
    f.write_text(KEY + "\n")
    monkeypatch.setenv("MERCATOR_API_KEY_FILE", str(f))
    monkeypatch.setenv("MERCATOR_API_KEY", "ignored")
    c = client(WardenAuth.from_env("MERCATOR"))
    assert c.get("/").json()["auth"] == f"Bearer {KEY}"
    rotated = "mct_" + "B" * 43
    new = tmp_path / "key.new"
    new.write_text(rotated)
    os.replace(new, f)  # how a Secret volume swaps: a new inode
    assert c.get("/").json()["auth"] == f"Bearer {rotated}"


def test_from_env_value(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("MERCATOR_API_KEY_FILE", raising=False)
    monkeypatch.setenv("MERCATOR_API_KEY", f" {KEY} ")
    assert client(WardenAuth.from_env("MERCATOR")).get("/").json()["auth"] == f"Bearer {KEY}"


@pytest.mark.parametrize("value", [None, "", "   "])
def test_from_env_refuses_missing_or_empty(monkeypatch: pytest.MonkeyPatch, value: str | None) -> None:
    monkeypatch.delenv("MERCATOR_API_KEY_FILE", raising=False)
    if value is None:
        monkeypatch.delenv("MERCATOR_API_KEY", raising=False)
    else:
        monkeypatch.setenv("MERCATOR_API_KEY", value)
    with pytest.raises(ValueError, match="MERCATOR_API_KEY"):
        WardenAuth.from_env("MERCATOR")


def test_empty_or_missing_file_fails_at_construction(tmp_path: Path) -> None:
    (tmp_path / "empty").write_text("\n")
    with pytest.raises(ValueError, match="empty"):
        WardenAuth(key_file=tmp_path / "empty")
    with pytest.raises(FileNotFoundError):
        WardenAuth(key_file=tmp_path / "missing")


def test_exactly_one_source() -> None:
    with pytest.raises(ValueError, match="exactly one"):
        WardenAuth()
    with pytest.raises(ValueError, match="exactly one"):
        WardenAuth(KEY, key_file=Path("/x"))
