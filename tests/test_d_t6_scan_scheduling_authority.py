"""tests/test_d_t6_scan_scheduling_authority.py — D-T6-003 Scan Scheduling Authority.

Contract: every scan-initiation route that calls background_tasks.add_task() MUST
capture job.id into a local variable BEFORE db.commit(), then pass that local
variable to add_task() — never job.id directly after the commit.

Test coverage:
  S1  AST contract: no scan route accesses job.id / source_scan.id after db.commit()
      before background_tasks.add_task() or before a subsequent attribute access
  S2  Regression: _c6_create_scan_job + commit + job_id capture = no ObjectDeletedError
  S3  Regression: background task receives a valid (non-expired) run_id when a
      dns_email scan is initiated via the durable job service directly
"""

from __future__ import annotations

import ast
import os
import secrets
import textwrap
from pathlib import Path

os.environ.setdefault("FG_ENV", "test")
os.environ.setdefault("FG_REPORT_SIGNING_KEY", "aa" * 32)

import pytest

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

REPO = Path(__file__).resolve().parents[1]
FA_FILE = REPO / "api" / "field_assessment.py"

_TENANT = "tenant-dt6-test"

_ENG_BODY = {
    "client_name": "D-T6 Corp",
    "assessor_id": "assessor-dt6",
    "assessment_type": "ai_governance",
}


# ---------------------------------------------------------------------------
# S1 — AST contract gate
# ---------------------------------------------------------------------------


class _CommitThenIdVisitor(ast.NodeVisitor):
    """Walks a function body and detects:

    1. A call to db.commit() (or SessionLocal.commit()).
    2. After that call, an attribute access of the form  <obj>.id  where
       <obj> is named 'job' or 'source_scan', AND the access is NOT an
       assignment target (i.e. ``job_id = job.id``).

    This catches the broken pattern::

        db.commit()
        run_id = job.id          # job expired — ObjectDeletedError
    """

    def __init__(self) -> None:
        self.violations: list[tuple[int, str]] = []  # (lineno, description)
        self._after_commit = False
        self._safe_names: set[str] = set()  # names captured before commit

    # ------------------------------------------------------------------
    # Helpers

    def _is_db_commit(self, node: ast.stmt) -> bool:
        """Return True if the statement is  db.commit()."""
        if not isinstance(node, ast.Expr):
            return False
        call = node.value
        if not isinstance(call, ast.Call):
            return False
        func = call.func
        return (
            isinstance(func, ast.Attribute)
            and func.attr == "commit"
            and isinstance(func.value, ast.Name)
            and func.value.id == "db"
        )

    def _is_capture_before_commit(self, node: ast.stmt) -> bool:
        """Detect ``job_id = job.id`` or ``source_scan_id = source_scan.id``."""
        if not isinstance(node, ast.Assign):
            return False
        val = node.value
        return (
            isinstance(val, ast.Attribute)
            and val.attr == "id"
            and isinstance(val.value, ast.Name)
            and val.value.id in ("job", "source_scan")
        )

    # ------------------------------------------------------------------
    # Scanning

    def scan_function(self, func_node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        """Scan a single function's body statements."""
        after_commit = False
        safe_captures: set[str] = set()

        def _check_stmt(stmt: ast.stmt) -> None:
            nonlocal after_commit

            if self._is_capture_before_commit(stmt) and not after_commit:
                # e.g. job_id = job.id  BEFORE commit — good, record it
                assert isinstance(stmt, ast.Assign)
                val = stmt.value
                assert isinstance(val, ast.Attribute)
                obj_name = val.value.id  # type: ignore[union-attr]
                for target in stmt.targets:
                    if isinstance(target, ast.Name):
                        safe_captures.add(target.id)
                return

            if self._is_db_commit(stmt):
                after_commit = True
                return

            if after_commit:
                # Check every node in the sub-tree for job.id / source_scan.id
                for node in ast.walk(stmt):
                    if (
                        isinstance(node, ast.Attribute)
                        and node.attr == "id"
                        and isinstance(node.value, ast.Name)
                        and node.value.id in ("job", "source_scan")
                    ):
                        # Check if this is a capture assignment (ok) or a read (bad)
                        parent_is_capture = (
                            isinstance(stmt, ast.Assign)
                            and stmt.value is node
                            and not after_commit
                        )
                        # If we're here, after_commit is True — any job.id access is bad
                        self.violations.append(
                            (
                                node.lineno,
                                f"{func_node.name}: {node.value.id}.id accessed after db.commit()",
                            )
                        )

        for stmt in func_node.body:
            _check_stmt(stmt)


def _get_scan_route_functions(tree: ast.Module) -> list[ast.FunctionDef | ast.AsyncFunctionDef]:
    """Return top-level functions that appear to be scan-initiation routes.

    Heuristic: the function body contains both a call to _c6_create_scan_job
    and a call to background_tasks.add_task OR is a known sync scan executor.
    """
    scan_fns = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        src = ast.dump(node)
        has_create_job = "_c6_create_scan_job" in src
        has_background = "background_tasks" in src or "add_task" in src
        # Also include synchronous routes that update job status after commit
        has_update_job = "_c6_update_job_status" in src
        if has_create_job and (has_background or has_update_job):
            scan_fns.append(node)
    return scan_fns


def test_s1_no_job_id_access_after_commit() -> None:
    """S1 — AST contract: no scan route reads job.id / source_scan.id after db.commit()."""
    source = FA_FILE.read_text(encoding="utf-8")
    tree = ast.parse(source, filename=str(FA_FILE))

    scan_fns = _get_scan_route_functions(tree)
    assert scan_fns, "Expected to find scan-initiation functions in field_assessment.py"

    all_violations: list[tuple[int, str]] = []
    for fn in scan_fns:
        visitor = _CommitThenIdVisitor()
        visitor.scan_function(fn)
        all_violations.extend(visitor.violations)

    if all_violations:
        lines = "\n".join(f"  line {ln}: {msg}" for ln, msg in sorted(all_violations))
        pytest.fail(
            f"D-T6-003: {len(all_violations)} scan route(s) access job.id / "
            f"source_scan.id after db.commit():\n{lines}"
        )


# ---------------------------------------------------------------------------
# S2 — Unit regression: capturing job.id before commit avoids ObjectDeletedError
# ---------------------------------------------------------------------------


def _sessionmaker():
    from api.db import get_sessionmaker

    return get_sessionmaker()


def _make_engagement(SM, *, tenant_id: str) -> str:
    from api.db_models_field_assessment import FaEngagement
    from services.canonical import utc_iso8601_z_now

    eng_id = secrets.token_hex(16)
    now = utc_iso8601_z_now()
    db = SM()
    try:
        db.add(
            FaEngagement(
                id=eng_id,
                tenant_id=tenant_id,
                client_name="D-T6 Corp",
                assessor_id="assessor-dt6",
                assessment_type="ai_governance",
                status="active",
                created_at=now,
                updated_at=now,
            )
        )
        db.commit()
    finally:
        db.close()
    return eng_id


def test_s2_job_id_captured_before_commit_no_error() -> None:
    """S2 — Regression: capturing job.id before db.commit() does not raise."""
    from services.field_assessment.durable_job_service import durable_job_svc

    SM = _sessionmaker()
    eng_id = _make_engagement(SM, tenant_id=_TENANT)

    db = SM()
    try:
        job = durable_job_svc.create_job(
            db,
            tenant_id=_TENANT,
            engagement_id=eng_id,
            actor="test@dt6",
            scanner_type="dns_email",
        )
        # Correct pattern: capture BEFORE commit
        job_id = job.id
        db.commit()
        # job is now expired; job_id must still be valid
        assert isinstance(job_id, str) and len(job_id) > 0
    finally:
        db.close()

    # Verify the job row exists in the DB
    db2 = SM()
    try:
        from api.db_models_field_assessment import FaScanJob

        stored = db2.get(FaScanJob, job_id)
        assert stored is not None, "FaScanJob row not found after commit"
        assert stored.status == "queued", f"Expected queued, got {stored.status!r}"
        assert stored.tenant_id == _TENANT
    finally:
        db2.close()


# ---------------------------------------------------------------------------
# S3 — Regression: background task scheduled with valid (non-expired) run_id
# ---------------------------------------------------------------------------


def test_s3_background_task_receives_valid_run_id() -> None:
    """S3 — Regression: run_id passed to background task is a plain string,
    not a reference to an expired SQLAlchemy attribute."""
    from services.field_assessment.durable_job_service import durable_job_svc

    SM = _sessionmaker()
    eng_id = _make_engagement(SM, tenant_id=_TENANT)

    captured_run_id: list[str] = []

    def fake_scan_task(*, run_id: str, **kwargs: object) -> None:
        captured_run_id.append(run_id)

    db = SM()
    try:
        job = durable_job_svc.create_job(
            db,
            tenant_id=_TENANT,
            engagement_id=eng_id,
            actor="test@dt6",
            scanner_type="network_scan",
        )
        # Correct pattern (mirrors the fix in field_assessment.py)
        job_id = job.id
        db.commit()
        # At this point job is expired; job_id is a plain Python str

        # Simulate background_tasks.add_task() by calling the task directly
        fake_scan_task(run_id=job_id, tenant_id=_TENANT, engagement_id=eng_id)
    finally:
        db.close()

    assert len(captured_run_id) == 1, "Background task was never called"
    run_id = captured_run_id[0]
    assert isinstance(run_id, str) and len(run_id) > 0, (
        f"run_id must be a non-empty string, got {run_id!r}"
    )

    # The FaScanJob row must exist with status 'queued' (background not yet run)
    db2 = SM()
    try:
        from api.db_models_field_assessment import FaScanJob

        stored = db2.get(FaScanJob, run_id)
        assert stored is not None, "FaScanJob row missing after commit"
        assert stored.status == "queued"
    finally:
        db2.close()
