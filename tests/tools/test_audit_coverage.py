"""tests/tools/test_audit_coverage.py — AUDIT-AUTHORITY-001 gate unit tests.

Covers the canonical portal audit authority recognition added in AUDIT-AUTHORITY-001:

  T1  Canonical portal delegate (pua.find_or_create_portal_user) counts as audited
  T2  Non-delegate pua call (pua.get_best_active_membership) does not count
  T3  Same method name on a different module alias is rejected (spoofing guard)
  T4  Approved delegate that no longer calls _emit_audit causes CONFIG ERROR (fail-closed)
  T5  Direct engagement-audit calls remain recognised (no regression)
  T6  Expired exceptions fail the gate (existing behaviour preserved)
  T7  UTC / local / Tokyo TZ all produce the same _policy_date result
  T8  Five portal routes (EXC-PORTAL-004–008) need no exceptions after AUDIT-AUTHORITY-001
  T9  Full gate run returns 0 and coverage_pct == 100.0
"""

from __future__ import annotations

import ast
import os
import sys
import textwrap
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any

import pytest

# ---------------------------------------------------------------------------
# Import gate module — tools/ci/ has __init__.py; repo root is on sys.path
# ---------------------------------------------------------------------------

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO))

from tools.ci.check_audit_coverage import (  # noqa: E402
    PORTAL_AUTHORITY_APPROVED_DELEGATES,
    _has_audit_call,
    _has_pua_delegate_call,
    _policy_date,
    _verify_pua_delegates,
    run,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _parse_func(src: str) -> ast.FunctionDef:
    """Parse a single function definition and return its AST node."""
    dedented = textwrap.dedent(src)
    tree = ast.parse(dedented)
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef):
            return node
    raise AssertionError("no FunctionDef found in src")


# ---------------------------------------------------------------------------
# T1 — canonical portal delegate counts as audited
# ---------------------------------------------------------------------------


def test_t1_canonical_pua_delegate_counts_as_audited() -> None:
    """pua.find_or_create_portal_user() is a verified delegate → audited=True."""
    src = """
    def portal_named_user_enroll(db):
        user = pua.find_or_create_portal_user(db, tenant_id="t")
        return user
    """
    func = _parse_func(src)
    assert _has_pua_delegate_call(func, PORTAL_AUTHORITY_APPROVED_DELEGATES)


def test_t1_all_five_portal_route_delegate_calls_are_recognized() -> None:
    """Each of the five EXC-PORTAL-00x routes calls at least one verified delegate."""
    cases = [
        # (route_name, delegate_called)
        ("portal_named_user_enroll", "find_or_create_portal_user"),
        ("portal_issue_invitation", "create_invitation"),
        ("portal_accept_invitation", "accept_invitation"),
        ("portal_revoke_named_session", "revoke_session"),
        ("portal_revoke_named_session_self", "revoke_session_by_token"),
    ]
    for route_name, delegate in cases:
        src = f"""
        def {route_name}(db):
            pua.{delegate}(db)
        """
        func = _parse_func(src)
        assert _has_pua_delegate_call(func, PORTAL_AUTHORITY_APPROVED_DELEGATES), (
            f"{route_name} → pua.{delegate}() should be recognised"
        )


# ---------------------------------------------------------------------------
# T2 — non-delegate pua call does not count as audited
# ---------------------------------------------------------------------------


def test_t2_non_delegate_pua_call_not_audited() -> None:
    """pua.get_best_active_membership() is NOT an audit delegate → audited=False."""
    src = """
    def some_route(db):
        membership = pua.get_best_active_membership(db, portal_user_id="u")
        return membership
    """
    func = _parse_func(src)
    assert not _has_pua_delegate_call(func, PORTAL_AUTHORITY_APPROVED_DELEGATES)


def test_t2_pua_readonly_functions_are_not_delegates() -> None:
    """Read-only pua helpers (lookup_, get_, validate_invitation) are not delegates."""
    non_delegates = [
        "get_active_membership",
        "get_best_active_membership",
        "get_invitation_by_token",
        "get_invitation_by_idempotency_key",
        "lookup_session_by_token",
    ]
    for name in non_delegates:
        src = f"""
        def route(db):
            pua.{name}(db)
        """
        func = _parse_func(src)
        assert not _has_pua_delegate_call(func, PORTAL_AUTHORITY_APPROVED_DELEGATES), (
            f"pua.{name}() should NOT count as audited"
        )


# ---------------------------------------------------------------------------
# T3 — spoofed same method name from another module is rejected
# ---------------------------------------------------------------------------


def test_t3_same_method_name_on_other_module_rejected() -> None:
    """other_mod.find_or_create_portal_user() does not satisfy the guard."""
    src = """
    def fake_route(db):
        other_mod.find_or_create_portal_user(db)
    """
    func = _parse_func(src)
    assert not _has_pua_delegate_call(func, PORTAL_AUTHORITY_APPROVED_DELEGATES)


def test_t3_bare_function_call_not_counted() -> None:
    """find_or_create_portal_user() without pua. prefix is not counted."""
    src = """
    def fake_route(db):
        find_or_create_portal_user(db)
    """
    func = _parse_func(src)
    # _has_pua_delegate_call requires pua.<method>; bare call should not match
    assert not _has_pua_delegate_call(func, PORTAL_AUTHORITY_APPROVED_DELEGATES)


def test_t3_nested_attribute_chain_rejected() -> None:
    """obj.pua.find_or_create_portal_user() (chained) is not the approved alias."""
    src = """
    def route(db):
        obj.pua.find_or_create_portal_user(db)
    """
    func = _parse_func(src)
    assert not _has_pua_delegate_call(func, PORTAL_AUTHORITY_APPROVED_DELEGATES)


# ---------------------------------------------------------------------------
# T4 — removing _emit_audit from an approved delegate causes CONFIG ERROR
# ---------------------------------------------------------------------------


def test_t4_broken_delegate_returns_config_errors(tmp_path: Path) -> None:
    """_verify_pua_delegates() returns errors when an approved delegate omits _emit_audit."""
    # Minimal authority file: has all approved delegates but one is missing _emit_audit
    delegates = sorted(PORTAL_AUTHORITY_APPROVED_DELEGATES)
    func_bodies = []
    for name in delegates:
        if name == "create_session":
            # create_session deliberately omits _emit_audit — simulate audit bypass
            func_bodies.append(f"def {name}(db): return None")
        else:
            func_bodies.append(
                f"def {name}(db): _emit_audit(db, event_type='x', tenant_id='t')"
            )

    authority_src = "\n".join(func_bodies)
    authority_file = tmp_path / "portal_user_authority.py"
    authority_file.write_text(authority_src, encoding="utf-8")

    errors = _verify_pua_delegates(authority_file=authority_file)
    assert errors, "expected CONFIG ERROR for delegate missing _emit_audit"
    assert any("create_session" in e for e in errors)


def test_t4_missing_delegate_function_is_a_config_error(tmp_path: Path) -> None:
    """If an approved delegate function is deleted from the file, gate reports error."""
    # File has no functions at all
    authority_file = tmp_path / "portal_user_authority.py"
    authority_file.write_text("# empty", encoding="utf-8")

    errors = _verify_pua_delegates(authority_file=authority_file)
    assert errors
    assert len(errors) == len(PORTAL_AUTHORITY_APPROVED_DELEGATES)


def test_t4_missing_authority_file_is_a_config_error(tmp_path: Path) -> None:
    """Non-existent authority file reports a config error."""
    missing = tmp_path / "does_not_exist.py"
    errors = _verify_pua_delegates(authority_file=missing)
    assert errors
    assert any("not found" in e for e in errors)


def test_t4_real_authority_file_passes_verification() -> None:
    """The real portal_user_authority.py passes delegate verification."""
    errors = _verify_pua_delegates()
    assert errors == [], f"unexpected errors: {errors}"


# ---------------------------------------------------------------------------
# T5 — direct engagement-audit calls remain recognised
# ---------------------------------------------------------------------------


def test_t5_direct_emit_engagement_audit_event_recognised() -> None:
    src = """
    def create_something(db):
        emit_engagement_audit_event(db, tenant_id="t", engagement_id="e",
                                    event_type="x", actor="a")
    """
    func = _parse_func(src)
    assert _has_audit_call(func)
    assert not _has_pua_delegate_call(func, PORTAL_AUTHORITY_APPROVED_DELEGATES)


def test_t5_audit_atomicity_svc_emit_recognised() -> None:
    src = """
    def update_something(db):
        audit_atomicity_svc.emit(db, tenant_id="t", engagement_id="e",
                                 event_type="x", actor="a", actor_type="service",
                                 reason_code="r", entity_type="e", entity_id="i",
                                 payload={})
    """
    func = _parse_func(src)
    assert _has_audit_call(func)


def test_t5_direct_audit_route_not_affected_by_pua_logic() -> None:
    """A route using emit_engagement_audit_event is audited even with no pua calls."""
    src = """
    def fa_route(db):
        emit_engagement_audit_event(db)
    """
    func = _parse_func(src)
    assert _has_audit_call(func)
    assert not _has_pua_delegate_call(func, PORTAL_AUTHORITY_APPROVED_DELEGATES)


# ---------------------------------------------------------------------------
# T6 — expired exceptions still fail the gate
# ---------------------------------------------------------------------------


def test_t6_expired_exception_fails_gate(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A route covered only by an expired exception produces a gate failure (exit 1)."""
    import yaml

    from tools.ci import check_audit_coverage as mod

    # Minimal portal_user_authority.py so delegate verification passes
    api_dir = tmp_path / "api"
    api_dir.mkdir()
    delegate_funcs = "\n".join(
        f"def {name}(db): _emit_audit(db)"
        for name in sorted(PORTAL_AUTHORITY_APPROVED_DELEGATES)
    )
    (api_dir / "portal_user_authority.py").write_text(delegate_funcs, encoding="utf-8")

    # Synthetic portal.py with one route that has no audit call
    portal_src = textwrap.dedent("""
        @router.post("/thing")
        def unaudited_route(db):
            return {}
    """)
    portal_file = api_dir / "portal.py"
    portal_file.write_text(portal_src, encoding="utf-8")

    # Exception for that route but expired yesterday
    yesterday = _policy_date().toordinal() - 1
    exp_date = date.fromordinal(yesterday).isoformat()
    exc_yaml = {
        "exceptions": [
            {
                "id": "EXC-TEST-001",
                "function_name": "unaudited_route",
                "file": "api/portal.py",
                "reason": "test",
                "owner": "test",
                "expiration_date": exp_date,
                "approval_reference": "test-ref",
            }
        ]
    }
    exc_file = tmp_path / "exc.yaml"
    exc_file.write_text(yaml.dump(exc_yaml), encoding="utf-8")

    monkeypatch.setattr(mod, "EXCEPTIONS_FILE", exc_file)
    monkeypatch.setattr(mod, "SCANNED_FILES", ["api/portal.py"])
    monkeypatch.setattr(mod, "REPO", tmp_path)

    result = mod.run(write_report=False)
    assert result == 1, "expired exception should cause gate failure"


# ---------------------------------------------------------------------------
# T7 — UTC / local / Tokyo TZ produce identical _policy_date result
# ---------------------------------------------------------------------------


def test_t7_policy_date_is_tz_independent() -> None:
    """_policy_date() returns UTC date regardless of TZ environment variable."""
    utc_date = datetime.now(timezone.utc).date()

    original_tz = os.environ.get("TZ")
    try:
        for tz_name in ("UTC", "America/New_York", "Asia/Tokyo", "Pacific/Honolulu"):
            os.environ["TZ"] = tz_name
            result = _policy_date()
            # Must equal UTC date — host TZ must never change the answer
            assert result == utc_date, (
                f"TZ={tz_name}: _policy_date()={result} != UTC={utc_date}"
            )
    finally:
        if original_tz is None:
            os.environ.pop("TZ", None)
        else:
            os.environ["TZ"] = original_tz


def test_t7_policy_date_returns_date_type() -> None:
    assert isinstance(_policy_date(), date)


# ---------------------------------------------------------------------------
# T8 — five portal routes need no exceptions after AUDIT-AUTHORITY-001
# ---------------------------------------------------------------------------


def test_t8_five_portal_routes_covered_without_exceptions() -> None:
    """EXC-PORTAL-004–008 are removed; the five routes are recognized via pua delegates."""
    from tools.ci.check_audit_coverage import (
        PORTAL_AUTHORITY_APPROVED_DELEGATES,
        _scan_mutation_routes,
    )

    # Run the real scan against the real api/portal.py
    routes = _scan_mutation_routes("api/portal.py", PORTAL_AUTHORITY_APPROVED_DELEGATES)
    route_map = {r["function_name"]: r for r in routes}

    formerly_excepted = [
        "portal_named_user_enroll",
        "portal_issue_invitation",
        "portal_accept_invitation",
        "portal_revoke_named_session",
        "portal_revoke_named_session_self",
    ]
    for fn in formerly_excepted:
        assert fn in route_map, f"route {fn} not found in scan"
        assert route_map[fn]["audited"], (
            f"{fn} must be recognised as audited via pua delegate (no exception needed)"
        )


def test_t8_exc_portal_ids_not_in_exceptions_yaml() -> None:
    """EXC-PORTAL-004 through EXC-PORTAL-008 are not in audit_exceptions.yaml."""
    import yaml

    exc_file = REPO / "tools" / "ci" / "audit_exceptions.yaml"
    raw = yaml.safe_load(exc_file.read_text(encoding="utf-8"))
    ids = {e["id"] for e in raw.get("exceptions", [])}
    for exc_id in (
        "EXC-PORTAL-004",
        "EXC-PORTAL-005",
        "EXC-PORTAL-006",
        "EXC-PORTAL-007",
        "EXC-PORTAL-008",
    ):
        assert exc_id not in ids, f"{exc_id} must be removed from audit_exceptions.yaml"


# ---------------------------------------------------------------------------
# T9 — full gate run returns 0 and coverage_pct == 100.0
# ---------------------------------------------------------------------------


def test_t9_full_gate_returns_zero() -> None:
    """Running the real gate against the real codebase returns 0 (no violations)."""
    result = run(write_report=False)
    assert result == 0, f"gate returned {result} — expected 0 (all routes covered)"


def test_t9_coverage_is_100_percent() -> None:
    """audit_coverage_report indicates 100% coverage after exception retirement."""
    from tools.ci.check_audit_coverage import (
        PORTAL_AUTHORITY_APPROVED_DELEGATES,
        SCANNED_FILES,
        _load_exceptions,
        _scan_mutation_routes,
    )

    all_routes: list[dict[str, Any]] = []
    for rel_path in SCANNED_FILES:
        all_routes.extend(
            _scan_mutation_routes(rel_path, PORTAL_AUTHORITY_APPROVED_DELEGATES)
        )

    exceptions, cfg_errors = _load_exceptions()
    assert cfg_errors == []

    violations = []
    expired = []
    excepted_count = 0

    for route in all_routes:
        if route["audited"]:
            continue
        key = f"{route['file']}::{route['function_name']}"
        exc = exceptions.get(key)
        if exc is None:
            violations.append(route["function_name"])
        elif exc["expired"]:
            expired.append(route["function_name"])
        else:
            excepted_count += 1

    total = len(all_routes)
    audited_count = sum(1 for r in all_routes if r["audited"]) + excepted_count
    pct = round(100 * audited_count / total, 1) if total else 0.0

    assert violations == [], f"unaudited routes with no exception: {violations}"
    assert expired == [], f"routes with expired exceptions: {expired}"
    assert pct == 100.0, f"coverage is {pct}%, expected 100.0%"
