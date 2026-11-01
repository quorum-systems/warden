"""warden: manage a service's API keys in its SOPS file and sync them to Vault for ESO.

    warden init    <file> --service bowdler --prefix bdl --grants moderations:create
    warden declare <file> --grants moderations:create,moderations:read   # the service's own grant list
    warden list    <file> [--show]
    warden issue   <file> <name> --grants '*'        # or 'moderations:create,...'
    warden issue   <file> <name> --grants '*' --rotate   # new token; the old one stays accepted as `previous`
    warden retire  <file> <name>                     # end a rotation: drop `previous`
    warden grants  <file> <name> --grants <spec>
    warden revoke  <file> <name>
    warden sync    <file> [--mount secret] [--apply] [--prune]

Every edit goes through sops, and refuses to run if the repo's .sops.yaml rule for the file wouldn't encrypt tokens.
Tokens are never in argv or on disk decrypted, and print only with `list --show`. `sync` shows the plan and changes
nothing without --apply; --prune also deletes consumers no longer in the file.
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from dataclasses import replace
from pathlib import Path

from warden import grants as g
from warden import sops, sync
from warden.keys import NAME, Key, KeysFile, new_token
from warden.vault import VaultCLI, VaultError


def _load(path: Path) -> KeysFile:
    return KeysFile.parse(sops.decrypt(path))


def _save(path: Path, index: int, k: Key) -> None:
    sops.set_item(path, index, k.doc())


def _mask(token: str) -> str:
    prefix, _, rest = token.partition("_")
    return f"{prefix}_{rest[:4]}…"


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(prog="warden", description=__doc__, formatter_class=argparse.RawTextHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("init")
    p.add_argument("file", type=Path)
    p.add_argument("--service", required=True)
    p.add_argument("--prefix", required=True)
    p.add_argument("--grants", required=True, help="comma-separated <resource>:<action> the service declares")
    p = sub.add_parser("declare")
    p.add_argument("file", type=Path)
    p.add_argument("--grants", required=True)
    p = sub.add_parser("list")
    p.add_argument("file", type=Path)
    p.add_argument("--show", action="store_true", help="print full tokens")
    for name in ("issue", "grants"):
        p = sub.add_parser(name)
        p.add_argument("file", type=Path)
        p.add_argument("name")
        p.add_argument("--grants", required=True, help="* or a comma-separated list of <resource>:<action>")
        if name == "issue":
            p.add_argument("--rotate", action="store_true", help="replace the token of an existing consumer")
    for name in ("revoke", "retire"):
        p = sub.add_parser(name)
        p.add_argument("file", type=Path)
        p.add_argument("name")
    p = sub.add_parser("sync")
    p.add_argument("file", type=Path)
    p.add_argument("--mount", default="secret")
    p.add_argument("--apply", action="store_true")
    p.add_argument("--prune", action="store_true")
    a = ap.parse_args(argv)

    try:
        _run(a)
    except (ValueError, VaultError) as e:
        sys.exit(f"warden: {e}")
    except subprocess.CalledProcessError as e:
        # argv holds no secrets; stderr is sops' or vault's own message. stdout may hold plaintext and is never shown.
        err = (e.stderr or b"").decode(errors="replace").strip()
        sys.exit(f"warden: {e.cmd[0]} {e.cmd[1]} failed (exit {e.returncode}): {err}")


def _run(a: argparse.Namespace) -> None:
    if a.cmd == "init":
        if a.file.exists():
            raise ValueError(f"{a.file} exists")
        doc = {"service": a.service, "prefix": a.prefix, "grants": a.grants, "keys": []}
        KeysFile.parse(doc)
        sops.create(a.file, doc)
        print(f"Created {a.file}")
        return

    kf = _load(a.file)
    keys = list(kf.keys)
    by_name = {k.name: i for i, k in enumerate(keys)}

    if a.cmd == "declare":
        declared = g.parse(a.grants)
        if g.ALL in declared:
            raise ValueError("a service declares its grants by name, not *")
        for k in keys:
            g.parse(k.grants, declared)
        sops.set_field(a.file, "grants", a.grants)
        print(f"Declared {a.grants} in {a.file}. The service's code must declare the same grants.")
    elif a.cmd == "retire":
        if a.name not in by_name or keys[by_name[a.name]].previous is None:
            raise ValueError(f"{a.name!r} isn't mid-rotation")
        _save(a.file, by_name[a.name], replace(keys[by_name[a.name]], previous=None))
        print(f"Retired the previous token of {a.name}. Run `warden sync --apply` to publish.")
    elif a.cmd == "list":
        _list(keys, a.show)
    elif a.cmd in ("issue", "grants"):
        _edit(a, kf, keys, by_name)
    elif a.cmd == "revoke":
        if a.name not in by_name:
            raise ValueError(f"no consumer {a.name!r}")
        sops.unset_item(a.file, by_name[a.name])
        print(f"Revoked {a.name} in {a.file}. Run `warden sync --apply --prune` to remove it from Vault.")
    elif a.cmd == "sync":
        _sync(kf, a.mount, a.apply, a.prune)


def _list(keys: list[Key], show: bool) -> None:
    width = max([4, *(len(k.name) for k in keys)])
    tw = max([5, *(len(k.token) if show else 10 for k in keys)])
    print(f"{'NAME':<{width}}  {'TOKEN':<{tw}}  {'ROTATING':<8}  GRANTS")
    for k in keys:
        token = k.token if show else _mask(k.token)
        print(f"{k.name:<{width}}  {token:<{tw}}  {'yes' if k.previous else '':<8}  {k.grants}")


def _edit(a: argparse.Namespace, kf: KeysFile, keys: list[Key], by_name: dict[str, int]) -> None:
    g.parse(a.grants, kf.grants)
    if not NAME.match(a.name):
        raise ValueError("name must be lowercase letters, digits and dashes")
    exists = a.name in by_name
    if a.cmd == "grants":
        if not exists:
            raise ValueError(f"no consumer {a.name!r}")
        _save(a.file, by_name[a.name], replace(keys[by_name[a.name]], grants=a.grants))
    elif exists and not a.rotate:
        raise ValueError(f"{a.name!r} already has a key; pass --rotate to replace it")
    else:
        old = keys[by_name[a.name]] if exists else None
        if old is not None and old.previous is not None:
            raise ValueError(f"{a.name!r} is already mid-rotation; `warden retire` it first")
        key = Key(a.name, new_token(kf.prefix), a.grants, previous=old.token if old else None)
        _save(a.file, by_name.get(a.name, len(keys)), key)
    print(f"{a.cmd}: {a.name} ({a.grants}) in {a.file}. Run `warden sync` to publish.")


def _sync(kf: KeysFile, mount: str, do_apply: bool, prune: bool) -> None:
    store = VaultCLI(mount)
    plan = sync.plan(kf, store)
    print("\n".join(plan.lines()) or "nothing to do")
    if not do_apply:
        print("\nPlan only; re-run with --apply to write" + ("" if not plan.stale else ", --prune to delete stale"))
        return
    sync.apply(plan, store, prune=prune)
    print(f"Applied: {len(plan.writes)} written, {len(plan.stale) if prune else 0} deleted.")
