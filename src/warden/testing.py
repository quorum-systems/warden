"""Test harness shared by every service that uses warden: a pytest plugin plus three plain functions.

Registered through the `pytest11` entry point, so it loads by itself wherever warden and pytest are installed; nothing
to add to a conftest. It is inert until a `debt.yaml` is collected, imports nothing from FastAPI at load, and needs no
extra: pytest is the consumer's own (pinning one here would only fight their pin).

* **Debt ratchet.** Every `debt.yaml` pytest collects (a service keeps it at `tests/debt.yaml`) becomes test items:
  `debt.yaml::_schema` plus one item per entry id. This replaces the byte-identical `tests/test_debt.py` that bowdler
  and mercator each carried; delete that file when adopting. The list is the services' record of known gaps against the
  testing standard, and the ratchet makes it shrink only. An entry needs `id`, `gap`, `owner`, `since`, `exit` and
  exactly one of `open_when` or `review_by`. `open_when` is a Python expression, evaluated with `ROOT` (the directory
  above the one holding debt.yaml) and `Path` in scope, that must stay true while the gap is real: when it turns false
  the entry fails with "delete it", so a fixed gap cannot linger. `review_by` is a date (`2026-11-30`, YAML date);
  past it the entry fails until it is fixed and deleted or re-reviewed with a new date. The expression is trusted
  repo content, evaluated with `eval` on purpose: it is the same file that is under code review as the tests.
  `check_debt(path)` runs the same checks as plain assertions for a service that wants them in its own test.
* **Docs check.** `check_docs(root, package, env_prefix, metrics)`: the README names every `<ENV_PREFIX>*` variable the
  source reads and every metric the service exports, and names no metric that does not exist.
* **Route guard.** `assert_routes_guarded(app, prefix, public)`: every route under the prefix depends on a warden
  `ServiceAuth.require(...)` guard. The same logic as `ServiceAuth.enforce`, usable from a test against a built app, so
  deleting the `enforce` call in app setup is not the only line of defence.
"""

from __future__ import annotations

import datetime as dt
import re
from collections.abc import Iterable, Iterator
from pathlib import Path
from types import ModuleType
from typing import TYPE_CHECKING, Any

import pytest
import yaml

if TYPE_CHECKING:
    from fastapi import FastAPI
    from prometheus_client import CollectorRegistry

REQUIRED = frozenset({"id", "gap", "owner", "since", "exit"})


def _check(ok: object, message: str) -> None:
    """`assert` without pytest's introspection: modules loaded as plugins are assertion-rewritten, and the rewrite
    appends a dump of the operands that buries these one-line messages."""
    if not ok:
        raise AssertionError(message)


# ---- debt ratchet ------------------------------------------------------------------------------------------------


def load_debt(path: Path) -> list[Any]:
    """The entries of a debt.yaml. An empty file is an empty list; anything but a list is a schema failure later."""
    return yaml.safe_load(path.read_text(encoding="utf-8")) or []


def check_schema(items: object) -> None:
    """Every entry has the required fields and exactly one of `open_when` / `review_by`, and ids are unique."""
    if not isinstance(items, list):
        raise AssertionError(f"debt.yaml must be a list of entries, got {type(items).__name__}")
    for e in items:
        _check(isinstance(e, dict), f"debt entry must be a mapping, got {e!r}")
    ids = [e.get("id") for e in items]
    _check(len(ids) == len(set(ids)), "duplicate debt ids")
    for e in items:
        _check(set(e) >= REQUIRED, f"{e.get('id')}: missing {sorted(REQUIRED - set(e))}")
        _check(("open_when" in e) != ("review_by" in e), f"{e['id']}: exactly one of open_when / review_by")


def check_entry(entry: dict[str, Any], root: Path, today: dt.date | None = None) -> None:
    """Fail if the gap looks fixed (`open_when` false) or the review date has passed. `today` is for tests."""
    if "open_when" in entry:
        still_open = eval(entry["open_when"], {"ROOT": root, "Path": Path})  # noqa: S307 - repo-owned, reviewed content
        _check(still_open, f"{entry['id']} looks fixed: delete it from tests/debt.yaml")
        return
    review_by = entry["review_by"]
    _check(isinstance(review_by, dt.date), f"{entry['id']}: review_by must be a YAML date, got {review_by!r}")
    _check(
        (today or dt.date.today()) <= review_by,
        f"{entry['id']} is past its review date ({review_by}): fix it, or re-review and set a new date",
    )


def check_debt(path: Path) -> None:
    """The whole ratchet on one file, as assertions: schema first, then every entry. `ROOT` is `path.parent.parent`."""
    items = load_debt(path)
    check_schema(items)
    for entry in items:
        check_entry(entry, path.parent.parent)


class DebtFile(pytest.File):
    def collect(self) -> Iterator[pytest.Item]:
        items = load_debt(self.path)
        root = self.path.parent.parent
        yield DebtItem.from_parent(self, name="_schema", items=items, entry=None, root=root)
        for n, entry in enumerate(items):
            if isinstance(entry, dict):  # a non-mapping entry is _schema's failure to report
                name = str(entry.get("id", f"entry-{n}"))
                yield DebtItem.from_parent(self, name=name, items=items, entry=entry, root=root)


class DebtItem(pytest.Item):
    def __init__(self, *, items: list[Any], entry: dict[str, Any] | None, root: Path, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self.items, self.entry, self.root = items, entry, root

    def runtest(self) -> None:
        if self.entry is None:
            check_schema(self.items)
        else:
            check_entry(self.entry, self.root)

    def repr_failure(self, excinfo: pytest.ExceptionInfo[BaseException], style: Any = None) -> str:
        # The assertion message is the whole story; a traceback into this module would bury it.
        return str(excinfo.value) if isinstance(excinfo.value, AssertionError) else str(super().repr_failure(excinfo))

    def reportinfo(self) -> tuple[Path, int, str]:
        return self.path, 0, f"debt: {self.name}"


def pytest_collect_file(file_path: Path, parent: pytest.Collector) -> DebtFile | None:
    return DebtFile.from_parent(parent, path=file_path) if file_path.name == "debt.yaml" else None


# ---- docs check --------------------------------------------------------------------------------------------------


def metric_families(source: ModuleType | CollectorRegistry) -> set[str]:
    """Family names (counters without `_total`) a service exports. Pass the service's CollectorRegistry after
    `install(..., registry=)` so warden's own series count too; a metrics module works as well (every collector object
    in its namespace, never a class), which is how 0.1.x tests did it."""
    if isinstance(source, ModuleType):
        return {
            fam.name
            for obj in vars(source).values()
            if hasattr(obj, "describe") and not isinstance(obj, type)
            for fam in obj.describe()
        }
    return {fam.name for fam in source.collect()}


def undocumented_env_vars(root: Path, package: str, env_prefix: str, readme: str) -> set[str]:
    """`<env_prefix>*` names the source under `src/<package>` mentions that the README does not show in backticks."""
    source = "\n".join(p.read_text() for p in (root / "src" / package).rglob("*.py"))
    read = set(re.findall(rf"\b{re.escape(env_prefix)}[A-Z_]+\b", source))
    assert read, f"src reads no {env_prefix} variables?"
    return {v for v in read if f"`{v}`" not in readme}


def undocumented_metrics(families: Iterable[str], readme: str) -> set[str]:
    """Exported families the README does not name (`name`, `name_total` or `name_info`, then a backtick or `{`)."""
    return {f for f in families if not re.search(rf"`{f}(_total|_info)?[`{{]", readme)}


def phantom_metrics(families: set[str], package: str, readme: str) -> set[str]:
    """`<package>_*` names the README shows that no exported family has (after dropping `_total` / `_info`)."""
    named = set(re.findall(rf"`({re.escape(package)}_[a-z_]+)[`{{]", readme))
    return {n for n in named if re.sub(r"_(total|info)$", "", n) not in families}


def check_docs(root: Path, package: str, env_prefix: str, metrics: ModuleType | CollectorRegistry) -> None:
    """The README (at `root/README.md`) documents every `env_prefix` variable the source reads and every exported
    metric, and documents no `<package>_*` metric that does not exist. All three findings are reported together."""
    readme = (root / "README.md").read_text(encoding="utf-8")
    families = metric_families(metrics)
    assert families, "the service exports no metrics?"
    problems = {
        "environment variables not in the README": undocumented_env_vars(root, package, env_prefix, readme),
        "metrics not in the README": undocumented_metrics(families, readme),
        "metrics in the README that are not exported": phantom_metrics(families, package, readme),
    }
    found = [f"{what}: {', '.join(sorted(names))}" for what, names in problems.items() if names]
    assert not found, "; ".join(found)


# ---- route guard -------------------------------------------------------------------------------------------------


def assert_routes_guarded(app: FastAPI, prefix: str = "/v1", public: Iterable[str] = ()) -> None:
    """Every route under `prefix` (every kind: mounts, plain Starlette routes and websockets count) depends on a
    `ServiceAuth.require(...)` guard, on the route, its router or the app, unless its path is in `public`. Fails with
    the list of `METHODS /path` that are open. Also fails if nothing lives under `prefix` (a typo would otherwise pass
    vacuously) or if a `public` entry matches no route. Call it on the built production app, not a fixture copy."""
    from warden.fastapi import is_warden_guard, unguarded_routes  # noqa: PLC0415 - keeps FastAPI out of plugin load

    assert any(getattr(r, "path", "").startswith(prefix) for r in app.routes), f"no routes under {prefix}"
    try:
        unguarded = unguarded_routes(app, prefix, public, is_warden_guard)
    except RuntimeError as e:
        raise AssertionError(str(e)) from e
    assert not unguarded, f"routes under {prefix} without a warden dependency: {', '.join(unguarded)}"
