import pytest

from warden import trace

TRACE_ID, SPAN_ID = "4bf92f3577b34da6a3ce929d0e0e4736", "00f067aa0ba902b7"


def test_valid_header() -> None:
    ctx = trace.parse([f"00-{TRACE_ID}-{SPAN_ID}-01"])
    assert ctx == trace.TraceContext(TRACE_ID, SPAN_ID, "01")
    assert ctx.traceparent == f"00-{TRACE_ID}-{SPAN_ID}-01"


def test_future_version_is_read_by_its_prefix() -> None:
    ctx = trace.parse([f"01-{TRACE_ID}-{SPAN_ID}-01-whatever"])
    assert ctx is not None
    assert ctx.trace_id == TRACE_ID


@pytest.mark.parametrize(
    "values",
    [
        [],
        [""],
        ["garbage"],
        [f"00-{TRACE_ID}-{SPAN_ID}"],
        [f"00-{TRACE_ID.upper()}-{SPAN_ID}-01"],
        [f"00-{'0' * 32}-{SPAN_ID}-01"],
        [f"00-{TRACE_ID}-{'0' * 16}-01"],
        [f"ff-{TRACE_ID}-{SPAN_ID}-01"],
        [f"00-{TRACE_ID}-{SPAN_ID}-01-extra"],
        [f"00-{TRACE_ID}-{SPAN_ID}-01", f"00-{TRACE_ID}-{SPAN_ID}-01"],
    ],
)
def test_invalid_is_ignored(values: list[str]) -> None:
    assert trace.parse(values) is None
