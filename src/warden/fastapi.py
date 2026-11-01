"""FastAPI integration: the server half of the Quorum service standard. Install with the `server` extra.

    auth = ServiceAuth(prefix="bdl", grants={"moderations:create"}, keys_file=Path(os.environ["BOWDLER_API_KEYS_FILE"]))
    install(app, service="bowdler")      # request id, trace context, one access line per request
    auth.enforce(app, prefix="/v1")      # at the end of app setup: fails if a /v1 route has no warden dependency

    @app.post("/v1/moderations")
    def moderate(req: ModerationRequest, who: Annotated[Principal, Depends(auth.require("moderations:create"))]): ...

A missing, malformed or unknown key is 401 `unauthorized`; a known key without the grant is 403 `forbidden`. Both are
raised as HTTPException with that `detail`, so the service's own exception handler shapes the body. The key map is
read once at construction and a bad one fails startup; a changed map takes effect on the next pod roll (Reloader).

The access line (logger `<service>.access`, INFO) carries request_id, trace_id, parent_span_id, consumer, method,
route (the template, never the raw path or query), status, outcome and duration_ms. `consumer` is the authenticated
key's name, or `unknown`. A handler can add `request.state.outcome` (a short bounded word) to it. Health, readiness
and metrics paths are not logged.
"""

from __future__ import annotations

import logging
import re
import time
import uuid
from collections.abc import Awaitable, Callable, Iterable
from pathlib import Path
from typing import Annotated, Any

from fastapi import FastAPI, Header, HTTPException, Request
from starlette.requests import HTTPConnection
from starlette.responses import Response

from warden import grants as g
from warden import trace
from warden.keys import HashMap, Principal

# No '.' or ':': an id shaped like an IP address would be logged and echoed.
REQUEST_ID = re.compile(r"[A-Za-z0-9_-]{1,128}")
UNLOGGED = frozenset({"/healthz", "/readyz", "/livez", "/metrics"})


class ServiceAuth:
    def __init__(self, prefix: str, grants: Iterable[str], keys_file: Path) -> None:
        self.declared = frozenset(g.check(x) for x in grants)
        self.keys = HashMap.from_json(prefix, keys_file.read_text(encoding="utf-8"), self.declared)
        self._dependencies: set[Callable[..., Principal]] = set()

    def require(self, grant: str) -> Callable[..., Principal]:
        if grant not in self.declared:
            raise ValueError(f"{grant!r} is not one of this service's declared grants")

        # HTTPConnection, not Request: FastAPI supplies it on websocket routes too.
        def dependency(request: HTTPConnection, authorization: Annotated[str | None, Header()] = None) -> Principal:
            scheme, _, token = (authorization or "").partition(" ")
            who = self.keys.principal(token.strip()) if scheme.lower() == "bearer" else None
            if who is None:
                request.state.outcome = "unauthorized"
                raise HTTPException(status_code=401, detail="unauthorized")
            request.state.principal = who
            if grant not in who.grants:
                request.state.outcome = "forbidden"
                raise HTTPException(status_code=403, detail="forbidden")
            return who

        self._dependencies.add(dependency)
        return dependency

    def enforce(self, app: FastAPI, prefix: str = "/v1", public: Iterable[str] = ()) -> None:
        """Fail if anything under `prefix` can be reached without a dependency from this ServiceAuth (on the route, its
        router or the app). Every kind of route counts: a mount, a plain Starlette route or a websocket under the
        prefix has no FastAPI dependencies and is reported unless listed in `public`. Call it after every route is
        registered; routes added later are not checked. `public` names paths that are deliberately open, and an entry
        that matches nothing is an error (a typo would otherwise leave the real route checked under a false belief)."""
        allowed = set(public)
        paths = {getattr(r, "path", "") for r in app.routes}
        if stale := sorted(allowed - paths):
            raise RuntimeError(f"public names no route: {', '.join(stale)}")
        unguarded = []
        for r in app.routes:
            path = getattr(r, "path", "")
            if not path.startswith(prefix) or path in allowed:
                continue
            dependant = getattr(r, "dependant", None)
            if dependant is None or not _uses(dependant, self._dependencies):
                methods = getattr(r, "methods", None) or {type(r).__name__}
                unguarded.append(f"{','.join(sorted(methods))} {path}")
        if unguarded:
            raise RuntimeError(f"routes under {prefix} without a warden dependency: {', '.join(unguarded)}")


def _uses(dependant: Any, calls: set[Callable[..., Principal]]) -> bool:
    return any(d.call in calls or _uses(d, calls) for d in dependant.dependencies)


def install(app: FastAPI, service: str, unlogged: Iterable[str] = UNLOGGED) -> None:
    """Add the request-id, trace-context and access-line middleware."""
    access = logging.getLogger(f"{service}.access")
    quiet = frozenset(unlogged)

    @app.middleware("http")
    async def context(request: Request, call_next: Callable[[Request], Awaitable[Response]]) -> Response:
        rid = request.headers.get("x-request-id", "")
        rid = rid if REQUEST_ID.fullmatch(rid) else uuid.uuid4().hex
        request.state.request_id = rid
        ctx = trace.parse(request.headers.getlist("traceparent"))
        token = trace.current.set(ctx)
        started = time.perf_counter()
        status = 500
        try:
            response = await call_next(request)
            status = response.status_code
            response.headers["X-Request-Id"] = rid
            return response
        finally:
            trace.current.reset(token)
            if request.url.path not in quiet:
                principal = getattr(request.state, "principal", None)
                route = request.scope.get("route")
                access.info(
                    "request",
                    extra={
                        "request_id": rid,
                        "trace_id": ctx.trace_id if ctx else None,
                        "parent_span_id": ctx.parent_id if ctx else None,
                        "consumer": principal.name if principal else "unknown",
                        "method": request.method,
                        # The template, never the raw path: a path can carry anything the caller typed.
                        "route": getattr(route, "path", None),
                        "status": status,
                        "outcome": getattr(request.state, "outcome", None),
                        "duration_ms": round((time.perf_counter() - started) * 1000, 3),
                    },
                )
