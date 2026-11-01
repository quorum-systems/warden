"""The calling half of the Quorum service standard: an httpx auth that sends the consumer's key and forwards the
current trace. Install with the `client` extra. Works with httpx.Client and httpx.AsyncClient.

    mercator = httpx.Client(base_url="http://mercator.mercator.svc:8080", auth=WardenAuth.from_env("MERCATOR"))

`from_env("MERCATOR")` reads the key from `MERCATOR_API_KEY_FILE` (a file, the ExternalSecret mount; preferred) or
`MERCATOR_API_KEY`. A file is re-read when it changes, so a rotated key is picked up without a restart.

Every request gets `Authorization: Bearer <key>` and, inside a request handled under warden's middleware (or with
`warden.trace.current` set), the caller's `traceparent`. Headers the caller set explicitly are left alone. The key is
never logged and never put in a URL.
"""

from __future__ import annotations

import os
import threading
from collections.abc import Generator
from pathlib import Path

import httpx

from warden import trace


class WardenAuth(httpx.Auth):
    def __init__(self, key: str | None = None, *, key_file: Path | None = None) -> None:
        if (key is None) == (key_file is None):
            raise ValueError("give exactly one of key or key_file")
        self._key = key.strip() if key else None
        self._file = key_file
        self._seen: tuple[int, int] | None = None
        self._lock = threading.Lock()
        if self._file is not None:
            self._read()

    @classmethod
    def from_env(cls, name: str) -> WardenAuth:
        """From `<NAME>_API_KEY_FILE`, else `<NAME>_API_KEY`. Fails at construction if neither is set or it's empty."""
        path = os.environ.get(f"{name}_API_KEY_FILE")
        if path:
            return cls(key_file=Path(path))
        key = os.environ.get(f"{name}_API_KEY")
        if not key or not key.strip():
            raise ValueError(f"set {name}_API_KEY_FILE or {name}_API_KEY")
        return cls(key)

    def _read(self) -> str:
        assert self._file is not None
        with self._lock:
            st = self._file.stat()
            seen = (st.st_ino, st.st_mtime_ns)
            if seen != self._seen:
                key = self._file.read_text(encoding="utf-8").strip()
                if not key:
                    raise ValueError(f"{self._file} is empty")
                self._key, self._seen = key, seen
            assert self._key is not None
            return self._key

    @property
    def key(self) -> str:
        if self._file is not None:
            return self._read()
        assert self._key is not None
        return self._key

    def auth_flow(self, request: httpx.Request) -> Generator[httpx.Request, httpx.Response]:
        request.headers.setdefault("Authorization", f"Bearer {self.key}")
        ctx = trace.current.get()
        if ctx is not None:
            request.headers.setdefault("traceparent", ctx.traceparent)
        yield request
