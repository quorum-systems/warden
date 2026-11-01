from __future__ import annotations

import pytest

from warden import grants as g

DECLARED = {"moderations:create", "moderations:read"}


def test_star_expands_to_declared() -> None:
    assert g.parse("*", DECLARED) == DECLARED


def test_list_with_spaces() -> None:
    assert g.parse(" moderations:read , moderations:create", DECLARED) == DECLARED


@pytest.mark.parametrize(
    "spec", ["", "moderations", "Moderations:read", "moderations:write", "a:read,", "a:read,,b:read"]
)
def test_bad_format(spec: str) -> None:
    with pytest.raises(ValueError, match="grant"):
        g.parse(spec)


def test_undeclared_grant() -> None:
    with pytest.raises(ValueError, match="not declared"):
        g.parse("locations:read", DECLARED)
