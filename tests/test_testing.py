"""warden.testing: the debt ratchet is run for real (pytest on throwaway projects), the helpers directly."""

import datetime as dt
import json
from importlib.metadata import entry_points, version
from pathlib import Path
from typing import Annotated

import pytest
from fastapi import APIRouter, Depends, FastAPI
from prometheus_client import CollectorRegistry, Counter, Info

import warden
from warden.fastapi import ServiceAuth
from warden.keys import Principal
from warden.testing import (
    assert_routes_guarded,
    check_debt,
    check_docs,
    check_entry,
    check_schema,
    metric_families,
)

GOOD = {"id": "x", "gap": "g", "owner": "o", "since": "2026-01-01", "exit": "e"}


def test_the_plugin_is_registered_for_pytest() -> None:
    [ep] = [e for e in entry_points(group="pytest11") if e.name == "warden"]
    assert ep.value == "warden.testing"


def test_the_version_in_code_is_the_version_in_the_package() -> None:
    assert warden.__version__ == version("warden")


# ---- debt: through pytest, so collection, ids and failure text are what a service sees ----------------------------


def project(pytester: pytest.Pytester, debt: str) -> pytest.RunResult:
    (pytester.path / "tests").mkdir()
    (pytester.path / "tests" / "debt.yaml").write_text(debt)
    return pytester.runpytest("tests", "-v")


def test_open_and_in_date_entries_pass(pytester: pytest.Pytester) -> None:
    (pytester.path / "marker").write_text("")
    future = dt.date.today() + dt.timedelta(days=30)
    result = project(
        pytester,
        f"""
- {{id: dated, gap: g, owner: o, since: 2026-01-01, exit: e, review_by: {future}}}
- {{id: probed, gap: g, owner: o, since: 2026-01-01, exit: e, open_when: "(ROOT / 'marker').exists()"}}
""",
    )
    result.assert_outcomes(passed=3)  # _schema plus the two entries
    result.stdout.fnmatch_lines(["*debt.yaml::dated PASSED*", "*debt.yaml::probed PASSED*"])


def test_a_fixed_gap_fails_until_the_entry_is_deleted(pytester: pytest.Pytester) -> None:
    result = project(
        pytester,
        "- {id: gone, gap: g, owner: o, since: 2026-01-01, exit: e, open_when: \"(ROOT / 'absent').exists()\"}\n",
    )
    result.assert_outcomes(passed=1, failed=1)
    assert "gone looks fixed: delete it from tests/debt.yaml" in result.stdout.str()


def test_an_overdue_review_fails(pytester: pytest.Pytester) -> None:
    result = project(pytester, "- {id: stale, gap: g, owner: o, since: 2026-01-01, exit: e, review_by: 2020-01-01}\n")
    result.assert_outcomes(passed=1, failed=1)
    assert "stale is past its review date (2020-01-01)" in result.stdout.str()


@pytest.mark.parametrize(
    ("debt", "message"),
    [
        ("- {id: a, gap: g, owner: o, since: 2026-01-01, review_by: 2999-01-01}\n", "a: missing ['exit']"),
        ("- {id: a, gap: g, owner: o, since: 2026-01-01, exit: e}\n", "a: exactly one of open_when / review_by"),
        (
            "- {id: a, gap: g, owner: o, since: 2026-01-01, exit: e, review_by: 2999-01-01, open_when: 'True'}\n",
            "a: exactly one of open_when / review_by",
        ),
        (
            "- {id: a, gap: g, owner: o, since: 2026-01-01, exit: e, review_by: 2999-01-01}\n"
            "- {id: a, gap: g, owner: o, since: 2026-01-01, exit: e, review_by: 2999-01-01}\n",
            "duplicate debt ids",
        ),
        ("not: a list\n", "debt.yaml must be a list of entries, got dict"),
        ("- just a string\n", "debt entry must be a mapping"),
    ],
)
def test_schema_violations_fail_the_schema_item(pytester: pytest.Pytester, debt: str, message: str) -> None:
    result = project(pytester, debt)
    assert result.ret != 0
    assert "debt.yaml::_schema FAILED" in result.stdout.str()
    assert message in result.stdout.str()


def test_an_empty_debt_file_is_a_clean_ratchet(pytester: pytest.Pytester) -> None:
    project(pytester, "").assert_outcomes(passed=1)


def test_other_yaml_files_are_ignored(pytester: pytest.Pytester) -> None:
    (pytester.path / "other.yaml").write_text("not: debt")
    pytester.runpytest().assert_outcomes()  # collects nothing, and nothing errors


# ---- debt: the plain functions ----------------------------------------------------------------------------------


def test_check_entry_review_date_boundary() -> None:
    entry = GOOD | {"review_by": dt.date(2026, 11, 30)}
    check_entry(entry, Path("."), today=dt.date(2026, 11, 30))  # the review day itself is still in date
    with pytest.raises(AssertionError, match="past its review date"):
        check_entry(entry, Path("."), today=dt.date(2026, 12, 1))


def test_check_entry_rejects_a_review_date_that_yaml_did_not_parse() -> None:
    entry = GOOD | {"review_by": "2026-11-30 maybe"}
    with pytest.raises(AssertionError, match="must be a YAML date"):
        check_entry(entry, Path("."))


def test_check_schema_accepts_a_clean_list() -> None:
    check_schema([GOOD | {"review_by": dt.date(2999, 1, 1)}])
    check_schema([])


def test_check_debt_runs_the_whole_file(tmp_path: Path) -> None:
    (tmp_path / "tests").mkdir()
    path = tmp_path / "tests" / "debt.yaml"
    path.write_text("- {id: a, gap: g, owner: o, since: 2026-01-01, exit: e, open_when: \"ROOT.name == 'a_root'\"}\n")
    with pytest.raises(AssertionError, match="a looks fixed"):
        check_debt(path)
    root = tmp_path / "a_root"
    (root / "tests").mkdir(parents=True)
    (root / "tests" / "debt.yaml").write_text(path.read_text())
    check_debt(root / "tests" / "debt.yaml")  # ROOT is the directory above tests/


# ---- docs ------------------------------------------------------------------------------------------------------


@pytest.fixture
def service(tmp_path: Path) -> tuple[Path, CollectorRegistry]:
    (tmp_path / "src" / "svc").mkdir(parents=True)
    (tmp_path / "src" / "svc" / "config.py").write_text('A = env("SVC_PORT")\nB = env("SVC_MODE")\n')
    (tmp_path / "README.md").write_text(
        "Set `SVC_PORT` and `SVC_MODE`. Metrics: `svc_jobs_total{kind}` and `svc_build_info{}`.\n"
    )
    registry = CollectorRegistry()
    Counter("svc_jobs_total", "jobs", ["kind"], registry=registry)
    Info("svc_build", "build", registry=registry)
    return tmp_path, registry


def test_docs_pass_when_readme_and_service_agree(service: tuple[Path, CollectorRegistry]) -> None:
    root, registry = service
    check_docs(root, "svc", "SVC_", registry)


def test_docs_report_every_kind_of_drift_together(service: tuple[Path, CollectorRegistry]) -> None:
    root, registry = service
    (root / "src" / "svc" / "more.py").write_text('C = env("SVC_NEW")\n')
    Counter("svc_quiet_total", "q", registry=registry)
    (root / "README.md").write_text(
        "`SVC_PORT` `SVC_MODE` `svc_jobs_total{kind}` `svc_build_info{}` `svc_ghost_total{}`\n"
    )
    with pytest.raises(AssertionError) as e:
        check_docs(root, "svc", "SVC_", registry)
    assert "environment variables not in the README: SVC_NEW" in str(e.value)
    assert "metrics not in the README: svc_quiet" in str(e.value)
    assert "not exported: svc_ghost_total" in str(e.value)


def test_docs_fail_on_a_service_that_reads_no_settings(service: tuple[Path, CollectorRegistry]) -> None:
    root, registry = service
    with pytest.raises(AssertionError, match="reads no OTHER_ variables"):
        check_docs(root, "svc", "OTHER_", registry)


def test_metric_families_accepts_a_metrics_module(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    (tmp_path / "svcmetrics.py").write_text(
        "from prometheus_client import CollectorRegistry, Counter, Info\nR = CollectorRegistry()\n"
        'jobs = Counter("svc_jobs_total", "jobs", registry=R)\n'
    )
    monkeypatch.syspath_prepend(str(tmp_path))
    import svcmetrics  # type: ignore[import-not-found]  # noqa: PLC0415 - written a line above

    assert metric_families(svcmetrics) == {"svc_jobs"}


# ---- route guard -------------------------------------------------------------------------------------------------


def make_auth(tmp_path: Path) -> ServiceAuth:
    keys = tmp_path / "keys.json"
    keys.write_text(json.dumps([]))
    return ServiceAuth("bdl", {"moderations:create"}, keys)


def test_every_route_guarded_passes_including_router_level(tmp_path: Path) -> None:
    auth = make_auth(tmp_path)
    app = FastAPI()

    @app.post("/v1/a")
    def a(who: Annotated[Principal, Depends(auth.require("moderations:create"))]) -> None: ...

    router = APIRouter(prefix="/v1/r", dependencies=[Depends(auth.require("moderations:create"))])

    @router.get("/b")
    def b() -> None: ...

    app.include_router(router)

    @app.get("/healthz")
    def healthz() -> None: ...

    assert_routes_guarded(app, "/v1")


def test_an_open_route_is_named(tmp_path: Path) -> None:
    app = FastAPI()
    make_auth(tmp_path)

    @app.get("/v1/open")
    def open_() -> None: ...

    with pytest.raises(AssertionError, match=r"GET /v1/open"):
        assert_routes_guarded(app)
    assert_routes_guarded(app, public=["/v1/open"])


def test_a_typo_in_the_prefix_or_public_cannot_pass_vacuously(tmp_path: Path) -> None:
    auth = make_auth(tmp_path)
    app = FastAPI()

    @app.get("/v1/a")
    def a(who: Annotated[Principal, Depends(auth.require("moderations:create"))]) -> None: ...

    with pytest.raises(AssertionError, match="no routes under /v2"):
        assert_routes_guarded(app, "/v2")
    with pytest.raises(AssertionError, match="public names no route: /v1/typo"):
        assert_routes_guarded(app, public=["/v1/typo"])


def test_any_warden_guard_counts_where_enforce_wants_its_own(tmp_path: Path) -> None:
    """The documented difference: a test has no ServiceAuth instance, so it accepts any warden guard."""
    mine, other = make_auth(tmp_path), make_auth(tmp_path)
    app = FastAPI()

    @app.get("/v1/a")
    def a(who: Annotated[Principal, Depends(other.require("moderations:create"))]) -> None: ...

    assert_routes_guarded(app)
    with pytest.raises(RuntimeError, match="/v1/a"):
        mine.enforce(app)


def test_a_plain_function_that_looks_like_auth_is_not_a_guard() -> None:
    app = FastAPI()

    def fake() -> None: ...

    @app.get("/v1/a", dependencies=[Depends(fake)])
    def a() -> None: ...

    with pytest.raises(AssertionError, match="/v1/a"):
        assert_routes_guarded(app)
