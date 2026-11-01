"""W3C Trace Context (https://www.w3.org/TR/trace-context/), the part every Quorum service shares: parse the caller's
`traceparent`, hold it for the current request, and hand it to outgoing calls. No dependencies.

A service that runs an OpenTelemetry SDK creates spans of its own and propagates through it; this module is the floor
for every service, so logs carry the caller's trace id whether or not the service exports spans.
"""

from __future__ import annotations

import re
from contextvars import ContextVar
from dataclasses import dataclass

# version-traceid-parentid-flags. A future version may append fields after the flags.
TRACEPARENT = re.compile(r"([0-9a-f]{2})-([0-9a-f]{32})-([0-9a-f]{16})-([0-9a-f]{2})(-.*)?")


@dataclass(frozen=True, slots=True)
class TraceContext:
    trace_id: str
    parent_id: str
    flags: str

    @property
    def traceparent(self) -> str:
        return f"00-{self.trace_id}-{self.parent_id}-{self.flags}"


current: ContextVar[TraceContext | None] = ContextVar("warden_trace", default=None)


def parse(values: list[str]) -> TraceContext | None:
    """The trace context from the request's `traceparent` header values, or None. Two headers, version ff, a version
    00 header with extra fields, or an all-zero id make it invalid, as the spec says; an invalid header is ignored,
    never repaired or replaced with an invented id."""
    if len(values) != 1 or not (m := TRACEPARENT.fullmatch(values[0].strip())):
        return None
    version, trace_id, parent_id, flags, extra = m.groups()
    if version == "ff" or (version == "00" and extra) or set(trace_id) == {"0"} or set(parent_id) == {"0"}:
        return None
    return TraceContext(trace_id, parent_id, flags)
