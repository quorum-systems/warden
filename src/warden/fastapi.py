"""FastAPI integration.

    auth = ServiceAuth(prefix="bdl", grants={"moderations:create"}, keys_file=Path(os.environ["BOWDLER_API_KEYS_FILE"]))

    @app.post("/v1/moderations")
    def moderate(req: ModerationRequest, who: Principal = Depends(auth.require("moderations:create"))): ...

A missing, malformed or unknown key is 401 `unauthorized`; a known key without the grant is 403 `forbidden`. Both are
raised as HTTPException with that `detail`, so the service's own exception handler shapes the body. The key map is
read once at construction and a bad one fails startup; a changed map takes effect on the next pod roll (Reloader).
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from pathlib import Path
from typing import Annotated

from fastapi import Header, HTTPException

from warden import grants as g
from warden.keys import HashMap, Principal


class ServiceAuth:
    def __init__(self, prefix: str, grants: Iterable[str], keys_file: Path) -> None:
        self.declared = frozenset(g.check(x) for x in grants)
        self.keys = HashMap.from_json(prefix, keys_file.read_text(encoding="utf-8"), self.declared)

    def require(self, grant: str) -> Callable[..., Principal]:
        if grant not in self.declared:
            raise ValueError(f"{grant!r} is not one of this service's declared grants")

        def dependency(authorization: Annotated[str | None, Header()] = None) -> Principal:
            scheme, _, token = (authorization or "").partition(" ")
            who = self.keys.principal(token.strip()) if scheme.lower() == "bearer" else None
            if who is None:
                raise HTTPException(status_code=401, detail="unauthorized")
            if grant not in who.grants:
                raise HTTPException(status_code=403, detail="forbidden")
            return who

        return dependency
