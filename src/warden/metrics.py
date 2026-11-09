"""Prometheus metrics for the generic HTTP layer and auth, prefixed by the service name. Server extra only.

    registry = CollectorRegistry(auto_describe=True)
    metrics = install(app, service="bowdler", registry=registry)   # warden.fastapi
    auth.enforce(app, prefix="/v1")
    metrics.seed_routes(app, prefix="/v1")                          # zero-init, after every route exists

Series (`<service>` is the name passed to install):

* `<service>_http_requests_total{method,route,code}`: every request the middleware sees except the unlogged paths
  (health, readiness, metrics). `route` is the matched route template or the literal `unmatched`, so the label set is
  bounded by the code, never by what a caller types. `code` is the numeric status as a string, 500 when the request
  raised. The counting lives in the middleware, not in handlers, so a 413 from a body-size limit or a 500 from an
  unhandled exception is counted like any other answer.
* `<service>_http_request_duration_seconds{route}`: wall time through the whole stack, same route label and exclusions.
* `<service>_auth_failures_total{reason}`: `missing` (no bearer credential presented), `unknown` (a bearer token no key
  matches), `forbidden` (a known key without the grant). All three exist at 0 from startup. Only HTTP routes are
  counted: the counter is read off the request by the middleware, and a websocket never passes through it.

Why zero-init: a Prometheus counter does not exist until its first increment, so `rate()` over a series that has never
fired is empty rather than 0, `increase()` misses the first event after a restart (no previous sample to subtract) and
`absent()` alerts fire on a healthy service. `auth_failures_total` is seeded for its three fixed reasons. The request
counter has an open label space (a 404 route name or a 503 code is not knowable up front), so only what is knowable is
seeded: `seed_routes` creates (method, route, code) for each route under a prefix, for the success codes you name.
Anything else appears on first use, so alert on ratios against the seeded series, never on `absent()` of a rare code.

`_created` timestamps are a process-wide switch in prometheus_client (`disable_created_metrics()`), not per registry;
the service's own metrics module already decides that, and warden leaves it alone.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from typing import TYPE_CHECKING, Literal, get_args

from prometheus_client import CollectorRegistry, Counter, Histogram

if TYPE_CHECKING:
    from fastapi import FastAPI

AuthFailure = Literal["missing", "unknown", "forbidden"]
AUTH_FAILURES: tuple[str, ...] = get_args(AuthFailure)

# The literal for a request that matched no route (a 404): one label value, however many paths callers probe.
UNMATCHED = "unmatched"

# 5 ms to 10 s: wide enough for a cache hit through a slow upstream. A service with a tighter SLO passes its own.
DEFAULT_BUCKETS: tuple[float, ...] = (0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0)

# HEAD and OPTIONS are added by Starlette and CORS, and are not what a service author thinks of as its routes.
_SKIP_METHODS = frozenset({"HEAD", "OPTIONS"})

# The method label is bounded here, not by the HTTP parser: httptools passes PURGE, LINK and the rest of llhttp's
# table, and h11 passes anything token-shaped. Everything else is one value.
_METHODS = frozenset({"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"})
OTHER_METHOD = "other"


class Metrics:
    """The three warden collectors on one registry. Built by `warden.fastapi.install`; hold the return value to call
    `seed_routes`. Registering twice on one registry raises ValueError (prometheus_client's duplicate-name check),
    which is the right failure: it means two installs, or a service still defining its own
    `<service>_auth_failures_total` (delete that one when adopting warden 0.2)."""

    def __init__(
        self,
        service: str,
        registry: CollectorRegistry,
        buckets: Sequence[float] = DEFAULT_BUCKETS,
    ) -> None:
        self.requests = Counter(
            f"{service}_http_requests_total",
            "HTTP requests by method, matched route template ('unmatched' for none) and numeric status code.",
            ["method", "route", "code"],
            registry=registry,
        )
        self.duration = Histogram(
            f"{service}_http_request_duration_seconds",
            "Wall time of HTTP requests through the middleware stack, by matched route template.",
            ["route"],
            buckets=tuple(buckets),
            registry=registry,
        )
        self.auth_failures = Counter(
            f"{service}_auth_failures_total",
            "Requests refused by warden auth, by reason: missing credential, unknown key, key without the grant.",
            ["reason"],
            registry=registry,
        )
        for reason in AUTH_FAILURES:
            self.auth_failures.labels(reason).inc(0)

    def observe(self, method: str, route: str, status: int, seconds: float) -> None:
        self.requests.labels(method if method in _METHODS else OTHER_METHOD, route, str(status)).inc()
        self.duration.labels(route).observe(seconds)

    def auth_failure(self, reason: str) -> None:
        self.auth_failures.labels(reason).inc()

    def seed_routes(self, app: FastAPI, prefix: str = "/v1", codes: Iterable[str] = ("200",)) -> None:
        """Create `(method, route, code)` at 0 for every HTTP route under `prefix`, plus its duration series, so a
        route that has not been called yet already exports 0 rather than nothing. Call it after every route is
        registered (next to `enforce`); routes added later are not seeded. `codes` are the success codes the routes
        return ("200", or "201" for a create). Mounts, websockets and HEAD/OPTIONS have no method here and are skipped.
        The set is bounded by the app's own routes."""
        wanted = tuple(codes)
        for route in app.routes:
            path = getattr(route, "path", "")
            if not path.startswith(prefix):
                continue
            for method in sorted(set(getattr(route, "methods", None) or ()) - _SKIP_METHODS):
                for code in wanted:
                    self.requests.labels(method, path, code).inc(0)
                self.duration.labels(path)
