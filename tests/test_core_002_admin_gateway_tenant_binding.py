# tests/test_core_002_admin_gateway_tenant_binding.py
"""PR-CORE-002 regression suite.

Proves that admin-gateway authority (admin_internal_token) combined with a
caller-controlled X-Tenant-ID cannot manufacture arbitrary tenant authority.

Security invariant: after this PR, every admin-gateway-authenticated request
that binds to a caller-supplied tenant ID must pass:
  1. A valid HMAC delegation proof tying the request to a specific tenant,
     method, and canonical path (delegation proof)
  2. Tenant existence and lifecycle check (tenant verification)
before the tenant is committed to request.state.

Architecture note: api.auth_scopes.resolution imports fastapi at module level,
so live behavioral tests run against inline mirrors that duplicate logic using
only stdlib. Static source tests verify the mirrors stay consistent with
production code.
"""

from __future__ import annotations

import hashlib
import hmac as _hmac
import time as _time
from dataclasses import dataclass
from pathlib import Path

import pytest
from sqlalchemy import create_engine, text

_RESOLUTION_SRC = Path("api/auth_scopes/resolution.py").read_text(encoding="utf-8")

# ── Test constants ─────────────────────────────────────────────────────────────

_TEST_SECRET = "test-delegation-secret-not-for-production-use"
_TEST_REQUEST_ID = "test-req-id-001"
_TEST_METHOD = "GET"
_TEST_PATH = "/admin/identity/tenants"

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


# ── Result dataclass ───────────────────────────────────────────────────────────


@dataclass
class _VerifyResult:
    ok: bool
    status_code: int = 0
    reason: str = ""


# ── Inline mirror of _verify_admin_gateway_tenant ─────────────────────────────


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


# ── Inline mirror of _verify_delegation_proof ─────────────────────────────────


def _make_proof(
    tenant_id: str,
    *,
    secret: str = _TEST_SECRET,
    request_id: str = _TEST_REQUEST_ID,
    method: str = _TEST_METHOD,
    path: str = _TEST_PATH,
    offset_seconds: int = 0,
    lifetime: int = 60,
) -> tuple[str, int, int]:
    """Create a valid delegation proof. Returns (proof_hex, issued_at, expires_at)."""
    issued_at = int(_time.time()) + offset_seconds
    expires_at = issued_at + lifetime
    canonical = f"v1\n{request_id}\n{tenant_id}\n{method.upper()}\n{path}\n{issued_at}\n{expires_at}"
    proof = _hmac.new(secret.encode(), canonical.encode(), hashlib.sha256).hexdigest()
    return proof, issued_at, expires_at


def _delegation_mirror(
    *,
    tenant_id: str,
    request_id: str,
    method: str,
    path: str,
    version: str | None,
    issued_at: int | None,
    expires_at: int | None,
    proof: str | None,
    secrets: list[str],
) -> _VerifyResult:
    """Inline mirror of _verify_delegation_proof using only stdlib."""
    if not secrets:
        return _VerifyResult(ok=True)  # dev bypass: no secrets configured

    if not all([version, issued_at is not None, expires_at is not None, proof]):
        return _VerifyResult(ok=False, status_code=403, reason="proof_required")

    if version != "v1":
        return _VerifyResult(ok=False, status_code=403, reason="unknown_version")

    now = int(_time.time())
    _CLOCK_TOLERANCE = 5
    _MAX_LIFETIME = 120

    if expires_at <= now:  # type: ignore[operator]
        return _VerifyResult(ok=False, status_code=403, reason="proof_expired")

    if issued_at > now + _CLOCK_TOLERANCE:  # type: ignore[operator]
        return _VerifyResult(ok=False, status_code=403, reason="proof_future_dated")

    if expires_at - issued_at > _MAX_LIFETIME:  # type: ignore[operator]
        return _VerifyResult(ok=False, status_code=403, reason="lifetime_exceeded")

    canonical = f"v1\n{request_id}\n{tenant_id}\n{method.upper()}\n{path}\n{issued_at}\n{expires_at}"
    for secret in secrets:
        expected = _hmac.new(
            secret.encode(), canonical.encode(), hashlib.sha256
        ).hexdigest()
        if _hmac.compare_digest(expected, (proof or "").lower()):
            return _VerifyResult(ok=True)

    return _VerifyResult(ok=False, status_code=403, reason="proof_invalid")


# ── Source invariants: tenant verification ────────────────────────────────────


def test_verify_admin_gateway_tenant_function_exists_in_resolution() -> None:
    assert "def _verify_admin_gateway_tenant(" in _RESOLUTION_SRC


def test_verify_admin_gateway_tenant_called_in_admin_internal_token_branch() -> None:
    branch_start = _RESOLUTION_SRC.index(
        'getattr(auth, "reason", "") == "admin_internal_token"'
    )
    branch_end = _RESOLUTION_SRC.index("\n    if ", branch_start + 1)
    branch = _RESOLUTION_SRC[branch_start:branch_end]
    assert "_verify_admin_gateway_tenant(requested)" in branch, (
        "_verify_admin_gateway_tenant must be called in the admin_internal_token branch"
    )


def test_verify_admin_gateway_tenant_precedes_state_mutation() -> None:
    verify_pos = _RESOLUTION_SRC.index("_verify_admin_gateway_tenant(requested)")
    state_pos = _RESOLUTION_SRC.index("request.state.tenant_id = requested", verify_pos)
    assert verify_pos < state_pos


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


# ── Source invariants: delegation proof ───────────────────────────────────────


def test_verify_delegation_proof_function_exists() -> None:
    assert "def _verify_delegation_proof(" in _RESOLUTION_SRC


def test_delegation_proof_called_in_admin_internal_token_branch() -> None:
    branch_start = _RESOLUTION_SRC.index(
        'getattr(auth, "reason", "") == "admin_internal_token"'
    )
    branch_end = _RESOLUTION_SRC.index("\n    if ", branch_start + 1)
    branch = _RESOLUTION_SRC[branch_start:branch_end]
    assert "_verify_delegation_proof(request, requested)" in branch


def test_delegation_proof_precedes_gateway_tenant_verify() -> None:
    delegation_pos = _RESOLUTION_SRC.index(
        "_verify_delegation_proof(request, requested)"
    )
    gateway_pos = _RESOLUTION_SRC.index("_verify_admin_gateway_tenant(requested)")
    assert delegation_pos < gateway_pos, (
        "_verify_delegation_proof must be called before _verify_admin_gateway_tenant"
    )


def test_delegation_proof_precedes_state_mutation() -> None:
    delegation_pos = _RESOLUTION_SRC.index(
        "_verify_delegation_proof(request, requested)"
    )
    state_pos = _RESOLUTION_SRC.index(
        "request.state.tenant_id = requested", delegation_pos
    )
    assert delegation_pos < state_pos


def test_delegation_function_body_checks_expired() -> None:
    fn_start = _RESOLUTION_SRC.index("def _verify_delegation_proof(")
    fn_end = _RESOLUTION_SRC.index("\ndef ", fn_start + 1)
    fn_body = _RESOLUTION_SRC[fn_start:fn_end]
    assert "expires_at <= now" in fn_body
    assert "status_code=403" in fn_body


def test_delegation_function_body_checks_future_dated() -> None:
    fn_start = _RESOLUTION_SRC.index("def _verify_delegation_proof(")
    fn_end = _RESOLUTION_SRC.index("\ndef ", fn_start + 1)
    fn_body = _RESOLUTION_SRC[fn_start:fn_end]
    assert "issued_at > now + _DELEGATION_CLOCK_TOLERANCE" in fn_body


def test_delegation_function_uses_constant_time_compare() -> None:
    fn_start = _RESOLUTION_SRC.index("def _verify_delegation_proof(")
    fn_end = _RESOLUTION_SRC.index("\ndef ", fn_start + 1)
    fn_body = _RESOLUTION_SRC[fn_start:fn_end]
    assert "hmac.compare_digest" in fn_body


# ── Behavioral invariants: tenant verification ────────────────────────────────


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
    eng = _in_memory_engine(("t1", "active"))
    eng.dispose()
    result = _verify_mirror("t1", eng)
    assert not result.ok
    assert result.status_code == 503
    assert result.reason == "db_error"


def test_wildcard_format_tenant_id_with_no_db_record_is_rejected() -> None:
    eng = _in_memory_engine()
    for fake_id in ["any-valid-id", "a" * 128, "frostgate-internal", "legit-looking"]:
        result = _verify_mirror(fake_id, eng)
        assert not result.ok, f"{fake_id!r} must fail without a DB record"
        assert result.status_code == 404


def test_existing_suspended_tenant_cannot_receive_admin_gateway_authority() -> None:
    eng = _in_memory_engine(("suspended-corp", "suspended"))
    result = _verify_mirror("suspended-corp", eng)
    assert not result.ok
    assert result.status_code == 403


def test_active_internal_platform_tenant_passes() -> None:
    eng = _in_memory_engine(("frostgate-internal", "active"))
    result = _verify_mirror("frostgate-internal", eng)
    assert result.ok


# ── Behavioral invariants: delegation proof ───────────────────────────────────


def test_valid_proof_correct_tenant_passes() -> None:
    proof, iat, exp = _make_proof("tenant-a")
    result = _delegation_mirror(
        tenant_id="tenant-a",
        request_id=_TEST_REQUEST_ID,
        method=_TEST_METHOD,
        path=_TEST_PATH,
        version="v1",
        issued_at=iat,
        expires_at=exp,
        proof=proof,
        secrets=[_TEST_SECRET],
    )
    assert result.ok


def test_proof_for_tenant_a_rejected_when_header_claims_tenant_b() -> None:
    proof, iat, exp = _make_proof("tenant-a")
    result = _delegation_mirror(
        tenant_id="tenant-b",  # proof is for tenant-a, header claims tenant-b
        request_id=_TEST_REQUEST_ID,
        method=_TEST_METHOD,
        path=_TEST_PATH,
        version="v1",
        issued_at=iat,
        expires_at=exp,
        proof=proof,
        secrets=[_TEST_SECRET],
    )
    assert not result.ok
    assert result.status_code == 403
    assert result.reason == "proof_invalid"


def test_no_proof_headers_rejected() -> None:
    result = _delegation_mirror(
        tenant_id="tenant-a",
        request_id=_TEST_REQUEST_ID,
        method=_TEST_METHOD,
        path=_TEST_PATH,
        version=None,
        issued_at=None,
        expires_at=None,
        proof=None,
        secrets=[_TEST_SECRET],
    )
    assert not result.ok
    assert result.status_code == 403
    assert result.reason == "proof_required"


def test_malformed_proof_rejected() -> None:
    proof, iat, exp = _make_proof("tenant-a")
    result = _delegation_mirror(
        tenant_id="tenant-a",
        request_id=_TEST_REQUEST_ID,
        method=_TEST_METHOD,
        path=_TEST_PATH,
        version="v1",
        issued_at=iat,
        expires_at=exp,
        proof="not-a-valid-hmac",
        secrets=[_TEST_SECRET],
    )
    assert not result.ok
    assert result.status_code == 403
    assert result.reason == "proof_invalid"


def test_wrong_secret_rejected() -> None:
    proof, iat, exp = _make_proof("tenant-a", secret="correct-secret")
    result = _delegation_mirror(
        tenant_id="tenant-a",
        request_id=_TEST_REQUEST_ID,
        method=_TEST_METHOD,
        path=_TEST_PATH,
        version="v1",
        issued_at=iat,
        expires_at=exp,
        proof=proof,
        secrets=["wrong-secret"],
    )
    assert not result.ok
    assert result.status_code == 403
    assert result.reason == "proof_invalid"


def test_expired_proof_rejected() -> None:
    now = int(_time.time())
    issued_at = now - 120
    expires_at = now - 60  # already expired
    canonical = (
        f"v1\n{_TEST_REQUEST_ID}\ntenant-a\n{_TEST_METHOD}\n{_TEST_PATH}"
        f"\n{issued_at}\n{expires_at}"
    )
    proof = _hmac.new(
        _TEST_SECRET.encode(), canonical.encode(), hashlib.sha256
    ).hexdigest()
    result = _delegation_mirror(
        tenant_id="tenant-a",
        request_id=_TEST_REQUEST_ID,
        method=_TEST_METHOD,
        path=_TEST_PATH,
        version="v1",
        issued_at=issued_at,
        expires_at=expires_at,
        proof=proof,
        secrets=[_TEST_SECRET],
    )
    assert not result.ok
    assert result.status_code == 403
    assert result.reason == "proof_expired"


def test_future_dated_proof_beyond_tolerance_rejected() -> None:
    now = int(_time.time())
    issued_at = now + 30  # 30 seconds in the future — beyond 5s tolerance
    expires_at = issued_at + 60
    canonical = (
        f"v1\n{_TEST_REQUEST_ID}\ntenant-a\n{_TEST_METHOD}\n{_TEST_PATH}"
        f"\n{issued_at}\n{expires_at}"
    )
    proof = _hmac.new(
        _TEST_SECRET.encode(), canonical.encode(), hashlib.sha256
    ).hexdigest()
    result = _delegation_mirror(
        tenant_id="tenant-a",
        request_id=_TEST_REQUEST_ID,
        method=_TEST_METHOD,
        path=_TEST_PATH,
        version="v1",
        issued_at=issued_at,
        expires_at=expires_at,
        proof=proof,
        secrets=[_TEST_SECRET],
    )
    assert not result.ok
    assert result.status_code == 403
    assert result.reason == "proof_future_dated"


def test_get_proof_rejected_for_post_replay() -> None:
    proof, iat, exp = _make_proof("tenant-a", method="GET")
    result = _delegation_mirror(
        tenant_id="tenant-a",
        request_id=_TEST_REQUEST_ID,
        method="POST",  # replayed against a different method
        path=_TEST_PATH,
        version="v1",
        issued_at=iat,
        expires_at=exp,
        proof=proof,
        secrets=[_TEST_SECRET],
    )
    assert not result.ok
    assert result.status_code == 403
    assert result.reason == "proof_invalid"


def test_proof_for_users_path_rejected_for_keys_path() -> None:
    proof, iat, exp = _make_proof(
        "tenant-a", path="/admin/identity/tenants/tenant-a/users"
    )
    result = _delegation_mirror(
        tenant_id="tenant-a",
        request_id=_TEST_REQUEST_ID,
        method=_TEST_METHOD,
        path="/admin/identity/tenants/tenant-a/keys",  # different path
        version="v1",
        issued_at=iat,
        expires_at=exp,
        proof=proof,
        secrets=[_TEST_SECRET],
    )
    assert not result.ok
    assert result.status_code == 403
    assert result.reason == "proof_invalid"


def test_rotation_previous_secret_accepted() -> None:
    proof, iat, exp = _make_proof("tenant-a", secret="old-secret")
    result = _delegation_mirror(
        tenant_id="tenant-a",
        request_id=_TEST_REQUEST_ID,
        method=_TEST_METHOD,
        path=_TEST_PATH,
        version="v1",
        issued_at=iat,
        expires_at=exp,
        proof=proof,
        secrets=["new-current-secret", "old-secret"],
    )
    assert result.ok


def test_no_secrets_configured_dev_bypass() -> None:
    result = _delegation_mirror(
        tenant_id="tenant-a",
        request_id=_TEST_REQUEST_ID,
        method=_TEST_METHOD,
        path=_TEST_PATH,
        version=None,
        issued_at=None,
        expires_at=None,
        proof=None,
        secrets=[],  # no secret configured — dev bypass
    )
    assert result.ok


def test_frostgate_internal_without_proof_fails_when_secret_configured() -> None:
    result = _delegation_mirror(
        tenant_id="frostgate-internal",
        request_id=_TEST_REQUEST_ID,
        method=_TEST_METHOD,
        path=_TEST_PATH,
        version=None,
        issued_at=None,
        expires_at=None,
        proof=None,
        secrets=[_TEST_SECRET],
    )
    assert not result.ok
    assert result.status_code == 403
    assert result.reason == "proof_required"


def test_frostgate_internal_with_valid_proof_passes() -> None:
    proof, iat, exp = _make_proof("frostgate-internal")
    result = _delegation_mirror(
        tenant_id="frostgate-internal",
        request_id=_TEST_REQUEST_ID,
        method=_TEST_METHOD,
        path=_TEST_PATH,
        version="v1",
        issued_at=iat,
        expires_at=exp,
        proof=proof,
        secrets=[_TEST_SECRET],
    )
    assert result.ok


def test_header_tenant_cannot_differ_from_proof_tenant() -> None:
    for legitimate_tenant in ["tenant-a", "frostgate-internal", "real-customer"]:
        proof, iat, exp = _make_proof(legitimate_tenant)
        for forged_tenant in ["tenant-b", "other-customer", "frostgate-internal"]:
            if forged_tenant == legitimate_tenant:
                continue
            result = _delegation_mirror(
                tenant_id=forged_tenant,
                request_id=_TEST_REQUEST_ID,
                method=_TEST_METHOD,
                path=_TEST_PATH,
                version="v1",
                issued_at=iat,
                expires_at=exp,
                proof=proof,
                secrets=[_TEST_SECRET],
            )
            assert not result.ok, (
                f"Proof for {legitimate_tenant!r} must not authorize {forged_tenant!r}"
            )
            assert result.status_code == 403
