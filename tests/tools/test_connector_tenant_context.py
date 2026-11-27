"""FG-ASSESSMENT-CONNECTOR-RLS-001 — the connector tenant-context guard bites.

Negative fixtures prove each prohibited pattern fails; positive fixtures prove
the canonical pattern passes; a mutation of the real source proves the guard
covers the real routes, not just fixtures.
"""

from __future__ import annotations

import shutil
import textwrap
from pathlib import Path

import pytest

from tools.ci import check_connector_tenant_context as chk

pytestmark = pytest.mark.contract

REPO = Path(__file__).resolve().parents[2]

_HEADER = """
def _c6_create_scan_job(db, **kw): ...
def _c6_update_job_status(db, **kw): ...
def set_tenant_context(db, tenant): ...
"""


def _route(body: str) -> str:
    return (
        _HEADER
        + textwrap.dedent(
            """
        def run_fixture_connector(engagement_id, request, db):
            tenant_id = resolve(request)
            job = _c6_create_scan_job(db, tenant_id=tenant_id)
            job_id = job.id
            if not _c6_update_job_status(db, job_id=job_id, status="running"):
                raise Conflict()
            db.commit()
        """
        )
        + textwrap.indent(textwrap.dedent(body), "    ")
    )


_VALID_TAIL = """
set_tenant_context(db, tenant_id)
try:
    rows = db.query(Thing).all()
    if not _c6_update_job_status(db, job_id=job_id, status="complete"):
        raise Lost(job_id)
    db.commit()
    return Response(rows=len(rows))
except Exception as exc:
    db.rollback()
    set_tenant_context(db, tenant_id)
    ok = _c6_update_job_status(db, job_id=job_id, status="failed")
    db.commit()
    raise
"""


def _errors(source: str) -> list[str]:
    return chk.check_source(source)[0]


def test_canonical_pattern_passes_and_is_discovered() -> None:
    errors, routes = chk.check_source(_route(_VALID_TAIL))
    assert errors == []
    assert routes == {"run_fixture_connector"}


@pytest.mark.parametrize(
    ("tail", "needle"),
    [
        # commit, then more DB work with no re-bind
        (
            _VALID_TAIL.replace("set_tenant_context(db, tenant_id)\ntry:", "try:", 1),
            "db.commit() is followed by more database work",
        ),
        # rollback in the failure path, then writes with no re-bind
        (
            _VALID_TAIL.replace(
                "    db.rollback()\n    set_tenant_context(db, tenant_id)\n",
                "    db.rollback()\n",
            ),
            "db.rollback() is followed by more database work",
        ),
        # re-bind from request data instead of the server-resolved tenant
        (
            _VALID_TAIL.replace(
                "set_tenant_context(db, tenant_id)\ntry:",
                "set_tenant_context(db, request.state.tenant_id)\ntry:",
                1,
            ),
            "db.commit() is followed by more database work",
        ),
        # re-bind not immediately after the commit
        (
            _VALID_TAIL.replace(
                "set_tenant_context(db, tenant_id)\ntry:",
                "log.info('x')\nset_tenant_context(db, tenant_id)\ntry:",
                1,
            ),
            "db.commit() is followed by more database work",
        ),
        # ignored compare-and-swap result
        (
            _VALID_TAIL.replace(
                '    if not _c6_update_job_status(db, job_id=job_id, status="complete"):\n'
                "        raise Lost(job_id)\n",
                '    _c6_update_job_status(db, job_id=job_id, status="complete")\n',
            ),
            "result of _c6_update_job_status() is ignored",
        ),
        (
            _VALID_TAIL.replace(
                '    ok = _c6_update_job_status(db, job_id=job_id, status="failed")\n',
                "    durable_job_svc.mark_failed(db, job_id=job_id, failure_reason='x')\n",
            ),
            "result of mark_failed() is ignored",
        ),
    ],
)
def test_prohibited_patterns_fail(tail: str, needle: str) -> None:
    source = _route(tail)
    # The fixture must still be a discoverable connector route ...
    if 'status="complete"' in source:
        assert "run_fixture_connector" in chk.check_source(source)[1]
    errors = _errors(source)
    # ... and the guard must name the violation.
    assert any(needle in e for e in errors), errors


def test_commit_followed_only_by_return_needs_no_rebind() -> None:
    tail = """
set_tenant_context(db, tenant_id)
if not _c6_update_job_status(db, job_id=job_id, status="complete"):
    raise Lost(job_id)
db.commit()
return Response(ok=True)
"""
    assert _errors(_route(tail)) == []


def test_background_routes_are_not_sync_connectors() -> None:
    source = _HEADER + textwrap.dedent(
        """
        def run_background_scan(db, background_tasks):
            job = _c6_create_scan_job(db)
            db.commit()
            db.query(Thing).all()
            background_tasks.add_task(worker, job.id)
            _c6_update_job_status(db, job_id="x", status="complete")
        """
    )
    errors, routes = chk.check_source(source)
    assert routes == set() and errors == []


def test_real_routes_pass_and_are_all_discovered() -> None:
    assert chk.check(REPO) == []
    _, routes = chk.check_source((REPO / chk.SOURCE).read_text(encoding="utf-8"))
    assert chk.EXPECTED_ROUTES <= routes


def _fake_repo(tmp_path: Path, text: str) -> Path:
    (tmp_path / "api").mkdir()
    (tmp_path / chk.SOURCE).write_text(text, encoding="utf-8")
    return tmp_path


def test_removing_a_real_rebind_fails(tmp_path: Path) -> None:
    text = (REPO / chk.SOURCE).read_text(encoding="utf-8")
    needle = "    db.commit()\n    # The tenant binding is transaction-local: re-bind"
    assert needle in text
    start = text.index(needle)
    rebind = "    set_tenant_context(db, tenant_id)\n"
    cut = text.index(rebind, start)
    mutated = text[:cut] + text[cut + len(rebind) :]
    errors = chk.check(_fake_repo(tmp_path, mutated))
    assert any("db.commit() is followed by more database work" in e for e in errors)


def test_guard_cannot_pass_by_covering_nothing(tmp_path: Path) -> None:
    errors = chk.check(_fake_repo(tmp_path, "def unrelated():\n    return 1\n"))
    assert any("guard would cover nothing" in e for e in errors)
    assert any("_c6_sync_connector_record_failure" in e for e in errors)


def test_real_source_copy_round_trips(tmp_path: Path) -> None:
    (tmp_path / "api").mkdir()
    shutil.copy(REPO / chk.SOURCE, tmp_path / chk.SOURCE)
    assert chk.check(tmp_path) == []


def test_preflight_without_the_admission_lock_fails(tmp_path: Path) -> None:
    text = (REPO / chk.SOURCE).read_text(encoding="utf-8")
    call = "    _c6_sync_connector_admission_lock(\n        db, tenant_id=tenant_id, engagement_id=engagement_id\n    )\n"
    assert text.count(call) == 1
    errors = chk.check(_fake_repo(tmp_path, text.replace(call, "")))
    assert any("must be _c6_sync_connector_admission_lock" in e for e in errors)


def test_job_created_before_preflight_fails() -> None:
    source = (REPO / chk.SOURCE).read_text(encoding="utf-8")
    tree = chk.ast.parse(source)
    route = next(
        n
        for n in tree.body
        if isinstance(n, chk.ast.FunctionDef) and n.name == "run_ai_vendor_governance"
    )
    # Move the scan-job creation ahead of the preflight call.
    create = next(
        i for i, s in enumerate(route.body) if "_c6_create_scan_job" in chk.ast.dump(s)
    )
    route.body.insert(0, route.body.pop(create))
    errors = chk.check_admission(tree, {"run_ai_vendor_governance"})
    assert any(
        "run_ai_vendor_governance: must call _c6_sync_connector_preflight" in e
        for e in errors
    )


def test_real_source_satisfies_admission_rule() -> None:
    source = (REPO / chk.SOURCE).read_text(encoding="utf-8")
    assert chk.check_admission(chk.ast.parse(source), set(chk.EXPECTED_ROUTES)) == []
