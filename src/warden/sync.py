"""Plan and apply the Vault side of a keys file.

Layout under the KV v2 mount (default `secret`), per service:

    k8s/services/<service>/keys                    {"keys.json": "<hash map JSON>"}   the service's ExternalSecret
    k8s/services/<service>/consumers/<name>        {"token": "<token>"}               that consumer's ExternalSecret

A plan names paths and consumers, never values.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field

from warden.keys import KeysFile
from warden.vault import Store


@dataclass(slots=True)
class Plan:
    writes: dict[str, dict[str, str]] = field(default_factory=dict)
    unchanged: list[str] = field(default_factory=list)
    stale: list[str] = field(default_factory=list)  # in Vault, not in the file: deleted only with prune

    def lines(self) -> list[str]:
        out = [f"write      {p}" for p in self.writes]
        out += [f"unchanged  {p}" for p in self.unchanged]
        out += [f"stale      {p}" for p in self.stale]
        return out


def root(kf: KeysFile) -> str:
    return f"k8s/services/{kf.service}"


def plan(kf: KeysFile, store: Store) -> Plan:
    p = Plan()
    desired = {f"{root(kf)}/keys": {"keys.json": json.dumps(kf.hash_map(), sort_keys=True)}}
    desired |= {f"{root(kf)}/consumers/{k.name}": {"token": k.token} for k in kf.keys}
    for path, data in desired.items():
        if store.get(path) == data:
            p.unchanged.append(path)
        else:
            p.writes[path] = data
    names = {k.name for k in kf.keys}
    p.stale = [f"{root(kf)}/consumers/{n}" for n in sorted(store.list(f"{root(kf)}/consumers")) if n not in names]
    return p


def apply(p: Plan, store: Store, prune: bool) -> None:
    # The service's hash map first: a service accepting a token its consumer doesn't hold yet is harmless; the reverse
    # is a 401. (What reaches pods first is still up to ESO's refresh and Reloader; rotation's `previous` covers that.)
    for path in sorted(p.writes, key=lambda x: not x.endswith("/keys")):
        store.put(path, p.writes[path])
    if prune:
        for path in p.stale:
            store.delete(path)
