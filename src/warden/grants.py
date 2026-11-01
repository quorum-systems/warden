"""Grant names and grant lists.

A grant is `<resource>:<action>`: the resource is a lowercase plural noun (dashes allowed), the action one of ACTIONS.
Each service declares the grants it checks; a key holds `*` (every grant its service declares) or a comma-separated
list of them.
"""

from __future__ import annotations

import re
from collections.abc import Iterable

ACTIONS = ("read", "create", "update", "delete", "admin")
GRANT = re.compile(rf"^[a-z][a-z0-9-]*:({'|'.join(ACTIONS)})$")
ALL = "*"


def check(grant: str) -> str:
    if not GRANT.match(grant):
        raise ValueError(f"grant {grant!r} is not <resource>:<{'|'.join(ACTIONS)}>")
    return grant


def parse(spec: str, declared: Iterable[str] | None = None) -> frozenset[str]:
    """`*` or `a:read,b:create` -> a set of grants. With `declared`, `*` expands and unknown grants are an error."""
    spec = spec.strip()
    known = frozenset(check(g) for g in declared) if declared is not None else None
    if spec == ALL:
        return known if known is not None else frozenset({ALL})
    parts = [p.strip() for p in spec.split(",")]
    if not spec or any(not p for p in parts):
        raise ValueError(f"grants {spec!r}: use * or a comma-separated list")
    out = frozenset(check(p) for p in parts)
    if known is not None and (unknown := out - known):
        raise ValueError(f"grants not declared by the service: {', '.join(sorted(unknown))}")
    return out
