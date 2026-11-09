"""FastAPI integration: the server half of the Quorum service standard. Install with the `server` extra.

    auth = ServiceAuth(prefix="bdl", grants={"moderations:create"}, keys_file=Path(os.environ["BOWDLER_API_KEYS_FILE"]))
    metrics = install(app, service="bowdler", registry=REGISTRY)   # request id, trace, access line, HTTP/auth metrics
    auth.enforce(app, prefix="/v1")      # at the end of app setup: fails if a /v1 route has no warden dependency
    metrics.seed_routes(app, prefix="/v1")  # zero-init the per-route series (only when a registry was given)

    @app.post("/v1/moderations")
    def moderate(req: ModerationRequest, who: Annotated[Principal, Depends(auth.require("moderations:create"))]): ...

A missing, malformed or unknown key is 401 `unauthorized`; a known key without the grant is 403 `forbidden`. Both are
raised as HTTPException with that `detail`, so the service's own exception handler shapes the body. The key map is
read once at construction and a bad one fails startup; a changed map takes effect on the next pod roll (Reloader).

The access line (logger `<service>.access`, INFO) carries request_id, trace_id, parent_span_id, consumer, method,
route (the template, never the raw path or query), status, outcome and duration_ms. `consumer` is the authenticated
key's name, or `unknown`. A handler can add `request.state.outcome` (a short bounded word) to it. Health, readiness
and metrics paths are not logged.

With `registry=` (a prometheus_client CollectorRegistry) `install` also records `<service>_http_requests_total`,
`<service>_http_request_duration_seconds` and `<service>_auth_failures_total` (see warden.metrics). They are counted in
the same middleware `finally` as the access line, so a response a handler never got to write (413 from a size limit, 500
from an unhandled exception) is counted too. Without a registry nothing is registered: 0.1.x behaviour.
"""

from __future__ import annotations

import logging
import re
import time
import uuid
from collections.abc import Awaitable, Callable, Iterable, Sequence
from pathlib import Path
from typing import Annotated, Any, NoReturn, overload

from fastapi import FastAPI, Header, HTTPException, Request
from prometheus_client import CollectorRegistry
from starlette.requests import HTTPConnection
from starlette.responses import Response

from warden import grants as g
from warden import trace
from warden.keys import HashMap, Principal
from warden.metrics import DEFAULT_BUCKETS, UNMATCHED, AuthFailure, Metrics

# No '.' or ':': an id shaped like an IP address would be logged and echoed.
REQUEST_ID = re.compile(r"[A-Za-z0-9_-]{1,128}")
UNLOGGED = frozenset({"/healthz", "/readyz", "/livez", "/metrics"})

# Set on every dependency `require` returns, so a test can recognise "some warden guard" without the ServiceAuth that
# made it (assert_routes_guarded in warden.testing). `enforce` still checks against its own instance's set.
GUARD_MARKER = "_warden_guard"


def _refuse(request: HTTPConnection, status: int, outcome: str, reason: AuthFailure) -> NoReturn:
    """Record why on the request (the middleware counts it, the access line reads the outcome), then raise. `detail`
    is the outcome word: the service's exception handler shapes the body."""
    request.state.outcome = outcome
    request.state.auth_failure = reason
    raise HTTPException(status_code=status, detail=outcome)


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
            token = token.strip()
            if scheme.lower() != "bearer" or not token:
                _refuse(request, 401, "unauthorized", "missing")  # no bearer credential was presented
            who = self.keys.principal(token)
            if who is None:
                _refuse(request, 401, "unauthorized", "unknown")
            request.state.principal = who
            if grant not in who.grants:
                _refuse(request, 403, "forbidden", "forbidden")
            return who

        setattr(dependency, GUARD_MARKER, True)
        self._dependencies.add(dependency)
        return dependency

    def enforce(self, app: FastAPI, prefix: str = "/v1", public: Iterable[str] = ()) -> None:
        """Fail if anything under `prefix` can be reached without a dependency from this ServiceAuth (on the route, its
        router or the app). Every kind of route counts: a mount, a plain Starlette route or a websocket under the
        prefix has no FastAPI dependencies and is reported unless listed in `public`. Call it after every route is
        registered; routes added later are not checked. `public` names paths that are deliberately open, and an entry
        that matches nothing is an error (a typo would otherwise leave the real route checked under a false belief)."""
        unguarded = unguarded_routes(app, prefix, public, lambda call: call in self._dependencies)
        if unguarded:
            raise RuntimeError(f"routes under {prefix} without a warden dependency: {', '.join(unguarded)}")


def unguarded_routes(app: FastAPI, prefix: str, public: Iterable[str], is_guard: Callable[[Any], bool]) -> list[str]:
    """`METHODS /path` for each route under `prefix` that no dependency satisfying `is_guard` protects, skipping the
    deliberately open `public` paths. Raises RuntimeError if a `public` entry names no route. Shared by
    `ServiceAuth.enforce` (guard = this instance's dependencies) and `warden.testing.assert_routes_guarded` (guard =
    any warden dependency), so the two cannot disagree about what counts as a route or as guarded."""
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
        if dependant is None or not _uses(dependant, is_guard):
            methods = getattr(r, "methods", None) or {type(r).__name__}
            unguarded.append(f"{','.join(sorted(methods))} {path}")
    return unguarded


def _uses(dependant: Any, is_guard: Callable[[Any], bool]) -> bool:
    return any(is_guard(d.call) or _uses(d, is_guard) for d in dependant.dependencies)


def is_warden_guard(call: Any) -> bool:
    return getattr(call, GUARD_MARKER, False) is True


@overload
def install(
    app: FastAPI,
    service: str,
    unlogged: Iterable[str] = UNLOGGED,
    *,
    registry: CollectorRegistry,
    buckets: Sequence[float] = DEFAULT_BUCKETS,
) -> Metrics: ...
@overload
def install(
    app: FastAPI,
    service: str,
    unlogged: Iterable[str] = UNLOGGED,
    registry: None = None,
    buckets: Sequence[float] = ...,
) -> None: ...
def install(
    app: FastAPI,
    service: str,
    unlogged: Iterable[str] = UNLOGGED,
    registry: CollectorRegistry | None = None,
    buckets: Sequence[float] = DEFAULT_BUCKETS,
) -> Metrics | None:
    """Add the request-id, trace-context and access-line middleware, and with `registry` the HTTP and auth metrics.

    `service` names the logger (`<service>.access`) and prefixes the metrics. `unlogged` are exact paths left out of
    the access line and of the request metrics (probes and the scrape itself would otherwise be most of the traffic).
    `registry` is the service's own CollectorRegistry; `None` (the default) registers and records nothing, which is
    exactly 0.1.x. `buckets` are the duration histogram's upper bounds in seconds.

    Returns the `Metrics` handle when a registry was given, else None; call `metrics.seed_routes(app, prefix)` after
    the routes exist to zero-init the per-route series. A second install for the same service on the same registry
    replaces the first's collectors. Raises ValueError if the registry holds a series of the same name that warden did
    not register (the service's own `<service>_auth_failures_total`)."""
    access = logging.getLogger(f"{service}.access")
    quiet = frozenset(unlogged)
    metrics = Metrics(service, registry, buckets) if registry is not None else None

    @app.middleware("http")
    async def context(request: Request, call_next: Callable[[Request], Awaitable[Response]]) -> Response:
        rid = request.headers.get("x-request-id", "")
        rid = rid if REQUEST_ID.fullmatch(rid) else uuid.uuid4().hex
        request.state.request_id = rid
        ctx = trace.parse(request.headers.getlist("traceparent"))
        token = trace.current.set(ctx)
        started = time.perf_counter()
        status = 500  # what an exception that escapes call_next becomes, for the log line and the metrics alike
        try:
            response = await call_next(request)
            status = response.status_code
            response.headers["X-Request-Id"] = rid
            return response
        finally:
            trace.current.reset(token)
            seconds = time.perf_counter() - started
            if request.url.path not in quiet:
                _log_access(access, request, rid, ctx, status=status, seconds=seconds)
                if metrics is not None:
                    metrics.observe(request.method, _route_label(request), status, seconds)
            if metrics is not None and (reason := getattr(request.state, "auth_failure", None)):
                metrics.auth_failure(reason)  # outside `quiet`: a refusal on a probe path is worth seeing

    return metrics


def _route_label(request: Request) -> str:
    """The matched route template, or `unmatched`. Never the raw path: that is whatever the caller typed."""
    path = getattr(request.scope.get("route"), "path", None)
    return path if isinstance(path, str) and path else UNMATCHED


def _log_access(
    access: logging.Logger, request: Request, rid: str, ctx: trace.TraceContext | None, *, status: int, seconds: float
) -> None:
    principal = getattr(request.state, "principal", None)
    access.info(
        "request",
        extra={
            "request_id": rid,
            "trace_id": ctx.trace_id if ctx else None,
            "parent_span_id": ctx.parent_id if ctx else None,
            "consumer": principal.name if principal else "unknown",
            "method": request.method,
            # The template, never the raw path: a path can carry anything the caller typed.
            "route": getattr(request.scope.get("route"), "path", None),
            "status": status,
            "outcome": getattr(request.state, "outcome", None),
            "duration_ms": round(seconds * 1000, 3),
        },
    )
