"""Keys: the token format, the SOPS keys file the operator edits, and the hash map a service loads.

Keys file (`gitops/secrets/<group>/<service>/service-keys.sops.yaml` in quorum/platform; only `token` is encrypted):

    service: bowdler          # also the Vault path segment
    prefix: bdl               # every token starts with `<prefix>_`
    grants: moderations:create   # comma list the service declares; every key's grants are checked against it
    keys:
      - name: marked-words    # consumer; shows up in the service's metrics and logs
        token: bdl_...
        previous: bdl_...     # only during a rotation: still accepted, no longer handed out
        grants: "*"           # or "moderations:create,..."

Hash map (what the service loads, synced to Vault and mounted by an ExternalSecret), JSON, one entry per accepted
token, so a consumer mid-rotation has two:

    [{"name": "marked-words", "sha256": "<hex>", "grants": "*"}]

A token is 256 random bits, so an unsalted SHA-256 can't be reversed and the hash map is not a secret.
"""

from __future__ import annotations

import hashlib
import json
import re
import secrets
from dataclasses import dataclass
from typing import Any

from warden import grants as g

NAME = re.compile(r"^[a-z0-9][a-z0-9-]{0,62}$")
PREFIX = re.compile(r"^[a-z]{2,8}$")
HASH = re.compile(r"^[0-9a-f]{64}$")


def new_token(prefix: str) -> str:
    return f"{prefix}_{secrets.token_urlsafe(32)}"


def digest(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


@dataclass(frozen=True, slots=True)
class Key:
    name: str
    token: str
    grants: str
    previous: str | None = None

    def doc(self) -> dict[str, str]:
        d = {"name": self.name, "token": self.token}
        if self.previous:
            d["previous"] = self.previous
        return d | {"grants": self.grants}


@dataclass(frozen=True, slots=True)
class KeysFile:
    service: str
    prefix: str
    grants: frozenset[str]
    keys: tuple[Key, ...]

    @classmethod
    def parse(cls, doc: dict[str, Any]) -> KeysFile:
        try:
            service, prefix = str(doc["service"]), str(doc["prefix"])
            declared = g.parse(str(doc["grants"]))
            if g.ALL in declared:
                raise ValueError("a service declares its grants by name, not *")
            keys = tuple(
                Key(
                    str(k["name"]), str(k["token"]), str(k["grants"]), str(k["previous"]) if k.get("previous") else None
                )
                for k in doc.get("keys") or []
            )
        except (KeyError, TypeError) as e:
            raise ValueError(f"keys file is missing or mistyped field {e}") from None
        if not NAME.match(service) or not PREFIX.match(prefix):
            raise ValueError("service must be a lowercase name and prefix 2-8 lowercase letters")
        names = [k.name for k in keys]
        for k in keys:
            if not NAME.match(k.name):
                raise ValueError(f"bad consumer name {k.name!r}")
            for t in (k.token, k.previous):
                if t is not None and not t.startswith(prefix + "_"):
                    raise ValueError(f"token for {k.name} doesn't start with {prefix}_")
            g.parse(k.grants, declared)
        if len(set(names)) != len(names):
            raise ValueError("duplicate consumer name in keys file")
        return cls(service, prefix, declared, keys)

    def hash_map(self) -> list[dict[str, str]]:
        return [
            {"name": k.name, "sha256": digest(t), "grants": k.grants}
            for k in self.keys
            for t in (k.token, k.previous)
            if t is not None
        ]


@dataclass(frozen=True, slots=True)
class Principal:
    """The caller, as a service sees it."""

    name: str
    grants: frozenset[str]


class HashMap:
    """The service side: hashes to consumers, checked in constant time against every entry."""

    def __init__(self, prefix: str, entries: list[dict[str, str]], declared: frozenset[str]) -> None:
        self.prefix = prefix
        self._entries: list[tuple[str, Principal]] = []
        for e in entries:
            if not NAME.match(e["name"]) or not HASH.match(e["sha256"]):
                raise ValueError(f"bad entry for {e.get('name')!r} in key map")
            self._entries.append((e["sha256"], Principal(e["name"], g.parse(e["grants"], declared))))
        # An empty map is valid: the service starts and answers 401 to everyone (e.g. after revoking the last key).

    @classmethod
    def from_json(cls, prefix: str, raw: str, declared: frozenset[str]) -> HashMap:
        return cls(prefix, json.loads(raw), declared)

    @property
    def names(self) -> set[str]:
        return {p.name for _, p in self._entries}

    def principal(self, token: str) -> Principal | None:
        if not token.startswith(self.prefix + "_") or len(token) > 128:
            return None
        presented = digest(token)
        found = None
        for h, p in self._entries:
            if secrets.compare_digest(h, presented):
                found = p
        return found
