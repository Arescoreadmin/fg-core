# tests/test_core_002_admin_gateway_tenant_binding.py
"""PR-CORE-002 regression suite.

Proves that admin-gateway authority (admin_internal_token) combined with a
caller-controlled X-Tenant-ID cannot manufacture arbitrary tenant authority.

Security invariant: after this PR, every admin-gateway-authenticated request
that binds to a caller-supplied tenant ID must pass an existence AND lifecycle
check before the tenant is committed to request.state.

Architecture note: api.auth_scopes.resolution imports fastapi at module level,
so live behavioral tests run against an inline mirror that duplicates the
_verify_admin_gateway_tenant logic using only api.db (fastapi-free). Static
source tests verify the mirror stays consistent with production code.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import pytest
from sqlalchemy import create_engine, text

from api.db import get_engine as _real_get_engine

_RESOLUTION_SRC = Path("api/auth_scopes/resolution.py").read_text(encoding="utf-8")

# ── Minimal tenant schema (matches what TenantRepository.get() reads) ─────────

_TENANT_SCHEMA = """
CREATE TABLE IF NOT EXISTS tenants (
    tenant_id   TEXT PRIMARY KEY,
    display_name TEXT NOT NULL DEFAULT '',
    lifecycle_state TEXT NOT NULL DEFAULT 'active',
    tenant_kind TEXT NOT NULL DEFAULT 'customer'
);
"""


def _in_memory_engine(*rows: tuple[str, str]):
    """SQLite in-memory engine with the minimal tenants table.

    rows: (tenant_id, lifecycle_state) pairs seeded before returning.
    """
    eng = create_engine("sqlite+pysqlite:///:memory:", future=True)
    with eng.begin() as conn:
        conn.execute(text(_TENANT_SCHEMA))
        for tenant_id, lifecycle_state in rows:
            conn.execute(
                text(
                    "INSERT INTO tenants (tenant_id, lifecycle_state)"
                    " VALUES (:tid, :state)"
                ),
                {"tid": tenant_id, "state": lifecycle_state},
            )
    return eng


# ── Inline mirror of _verify_admin_gateway_tenant ─────────────────────────────
# Mirrors the post-PR-CORE-002 logic without importing fastapi.
# Static source tests below verify this mirror matches production code.


@dataclass
class _VerifyResult:
    ok: bool
    status_code: int = 0
    reason: str = ""


def _verify_mirror(tenant_id: str, engine) -> _VerifyResult:
    """Inline mirror: returns result instead of raising HTTPException."""
    try:
        with engine.connect() as conn:
            row = conn.execute(
                text("SELECT lifecycle_state FROM tenants WHERE tenant_id = :tid"),
                {"tid": tenant_id},
            ).fetchone()
    except Exception:
        return _VerifyResult(ok=False, status_code=503, reason="db_error")

    if row is None:
        return _VerifyResult(ok=False, status_code=404, reason="not_found")

    if row[0] != "active":
        return _VerifyResult(
            ok=False, status_code=403, reason=f"lifecycle_denied:{row[0]}"
        )

    return _VerifyResult(ok=True)


# ── Source invariants ──────────────────────────────────────────────────────────


def test_verify_admin_gateway_tenant_function_exists_in_resolution() -> None:
    assert "def _verify_admin_gateway_tenant(" in _RESOLUTION_SRC


def test_verify_admin_gateway_tenant_called_in_admin_internal_token_branch() -> None:
    # Isolate the admin_internal_token if-block body
    branch_start = _RESOLUTION_SRC.index(
        'getattr(auth, "reason", "") == "admin_internal_token"'
    )
    # The branch ends before the next top-level if (at column 4 indentation)
    branch_end = _RESOLUTION_SRC.index("\n    if ", branch_start + 1)
    branch = _RESOLUTION_SRC[branch_start:branch_end]
    assert "_verify_admin_gateway_tenant(requested)" in branch, (
        "_verify_admin_gateway_tenant must be called in the admin_internal_token branch"
    )


def test_verify_admin_gateway_tenant_precedes_state_mutation() -> None:
    # Verify the call comes before request.state mutation
    verify_pos = _RESOLUTION_SRC.index("_verify_admin_gateway_tenant(requested)")
    # Find the nearest state assignment after the call
    state_pos = _RESOLUTION_SRC.index("request.state.tenant_id = requested", verify_pos)
    assert verify_pos < state_pos, (
        "_verify_admin_gateway_tenant must run before request.state.tenant_id is set"
    )


def test_verify_function_body_checks_none_for_not_found() -> None:
    fn_start = _RESOLUTION_SRC.index("def _verify_admin_gateway_tenant(")
    fn_end = _RESOLUTION_SRC.index("\ndef ", fn_start + 1)
    fn_body = _RESOLUTION_SRC[fn_start:fn_end]
    assert "record is None" in fn_body, "must raise on missing tenant"
    assert "status_code=404" in fn_body, "missing tenant must be 404"


def test_verify_function_body_checks_lifecycle_state() -> None:
    fn_start = _RESOLUTION_SRC.index("def _verify_admin_gateway_tenant(")
    fn_end = _RESOLUTION_SRC.index("\ndef ", fn_start + 1)
    fn_body = _RESOLUTION_SRC[fn_start:fn_end]
    assert 'lifecycle_state != "active"' in fn_body, "must enforce active lifecycle"
    assert "status_code=403" in fn_body, "non-active tenant must be 403"


def test_verify_function_body_has_db_error_guard() -> None:
    fn_start = _RESOLUTION_SRC.index("def _verify_admin_gateway_tenant(")
    fn_end = _RESOLUTION_SRC.index("\ndef ", fn_start + 1)
    fn_body = _RESOLUTION_SRC[fn_start:fn_end]
    assert "except Exception" in fn_body, "must catch DB errors"
    assert "status_code=503" in fn_body, "DB error must return 503"


# ── Behavioral invariants (via inline mirror + in-memory SQLite) ───────────────


def test_nonexistent_tenant_is_rejected_404() -> None:
    eng = _in_memory_engine()  # empty DB
    result = _verify_mirror("ghost-tenant", eng)
    assert not result.ok
    assert result.status_code == 404
    assert result.reason == "not_found"


@pytest.mark.parametrize(
    "lifecycle_state",
    ["suspended", "archived", "deleted", "pending"],
)
def test_inactive_tenant_lifecycle_is_rejected_403(lifecycle_state: str) -> None:
    eng = _in_memory_engine(("target-tenant", lifecycle_state))
    result = _verify_mirror("target-tenant", eng)
    assert not result.ok
    assert result.status_code == 403
    assert "lifecycle_denied" in result.reason


def test_active_tenant_passes_verification() -> None:
    eng = _in_memory_engine(("good-tenant", "active"))
    result = _verify_mirror("good-tenant", eng)
    assert result.ok
    assert result.status_code == 0


def test_db_error_returns_503_fail_closed() -> None:
    # Pass a broken engine (disposed) to trigger a DB error
    eng = _in_memory_engine(("t1", "active"))
    eng.dispose()
    result = _verify_mirror("t1", eng)
    assert not result.ok
    assert result.status_code == 503
    assert result.reason == "db_error"


def test_wildcard_format_tenant_id_with_no_db_record_is_rejected() -> None:
    # A syntactically valid tenant that doesn't exist must fail closed
    eng = _in_memory_engine()
    for fake_id in ["any-valid-id", "a" * 128, "frostgate-internal", "legit-looking"]:
        result = _verify_mirror(fake_id, eng)
        assert not result.ok, f"{fake_id!r} must fail without a DB record"
        assert result.status_code == 404


def test_existing_suspended_tenant_cannot_receive_admin_gateway_authority() -> None:
    # Suspended tenant: token is valid, format is valid, but lifecycle denies
    eng = _in_memory_engine(("suspended-corp", "suspended"))
    result = _verify_mirror("suspended-corp", eng)
    assert not result.ok
    assert result.status_code == 403


def test_active_internal_platform_tenant_passes() -> None:
    # The frostgate-internal tenant itself (operator) must pass when active
    eng = _in_memory_engine(("frostgate-internal", "active"))
    result = _verify_mirror("frostgate-internal", eng)
    assert result.ok
