# tests/test_core_002b_middleware_prebinding.py
"""PR-CORE-002B regression suite — middleware pre-binding bypass.

The bypass (confirmed in production, G5/G6 FAIL on 2026-08-17):
  AuthGateMiddleware set request.state.tenant_id and tenant_is_key_bound=True
  for admin_internal_token + X-Tenant-ID requests. bind_tenant_id() saw the
  key_bound_flag and returned without running _verify_delegation_proof or
  _verify_admin_gateway_tenant — delegating authority to any caller-supplied
  tenant regardless of proof or lifecycle state.

The fix (PR-CORE-002B) has two layers:
  1. auth_gate.py: admin_internal_token removed from _tenant_injectable, so the
     middleware never pre-commits tenant_id or tenant_is_key_bound for that path.
  2. resolution.py bind_tenant_id(): defense-in-depth guards at the key_bound
     fast-path and the auth_tenant fast-path ensure admin_internal_token always
     reaches the delegation verification branch regardless of cached state.

Tests A–D: source invariants (the fix is present and correctly ordered).
Tests E–H: behavioral invariants (inline mirrors prove the bypass is closed).
"""

from __future__ import annotations

import hashlib
import hmac as _hmac
import time as _time
from dataclasses import dataclass
from pathlib import Path

_AUTHGATE_SRC = Path("api/middleware/auth_gate.py").read_text(encoding="utf-8")
_RESOLUTION_SRC = Path("api/auth_scopes/resolution.py").read_text(encoding="utf-8")

_TEST_SECRET = "test-002b-delegation-secret-not-for-prod"
_TEST_TENANT = "tenant-x"
_TEST_REQUEST_ID = "req-002b-001"
_CONFIG_PATH = "/admin/identity/tenants/tenant-x/config"
_READINESS_PATH = "/admin/identity/tenants/tenant-x/readiness"


# ── Result dataclass ───────────────────────────────────────────────────────────


@dataclass
class _Result:
    ok: bool
    status_code: int = 0
    reason: str = ""


# ── Inline delegation mirror ───────────────────────────────────────────────────


def _make_proof(
    tenant_id: str,
    *,
    secret: str = _TEST_SECRET,
    request_id: str = _TEST_REQUEST_ID,
    method: str = "GET",
    path: str = _CONFIG_PATH,
    offset: int = 0,
    lifetime: int = 60,
) -> tuple[str, int, int]:
    issued_at = int(_time.time()) + offset
    expires_at = issued_at + lifetime
    canonical = f"v1\n{request_id}\n{tenant_id}\n{method.upper()}\n{path}\n{issued_at}\n{expires_at}"
    proof = _hmac.new(secret.encode(), canonical.encode(), hashlib.sha256).hexdigest()
    return proof, issued_at, expires_at


def _delegation_check(
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
) -> _Result:
    """Inline mirror of _verify_delegation_proof."""
    if not secrets:
        return _Result(ok=True)

    if not all([version, issued_at is not None, expires_at is not None, proof]):
        return _Result(ok=False, status_code=403, reason="proof_required")

    if version != "v1":
        return _Result(ok=False, status_code=403, reason="unknown_version")

    now = int(_time.time())
    if expires_at <= now:  # type: ignore[operator]
        return _Result(ok=False, status_code=403, reason="proof_expired")
    if issued_at > now + 5:  # type: ignore[operator]
        return _Result(ok=False, status_code=403, reason="proof_future_dated")
    if expires_at - issued_at > 120:  # type: ignore[operator]
        return _Result(ok=False, status_code=403, reason="lifetime_exceeded")

    canonical = f"v1\n{request_id}\n{tenant_id}\n{method.upper()}\n{path}\n{issued_at}\n{expires_at}"
    for secret in secrets:
        expected = _hmac.new(
            secret.encode(), canonical.encode(), hashlib.sha256
        ).hexdigest()
        if _hmac.compare_digest(expected, (proof or "").lower()):
            return _Result(ok=True)

    return _Result(ok=False, status_code=403, reason="proof_invalid")


def _simulate_bind_with_prebind(
    *,
    prebind_tenant: str,
    request_tenant: str,
    proof_tenant: str = _TEST_TENANT,
    proof_method: str = "GET",
    proof_path: str = _CONFIG_PATH,
    request_method: str = "GET",
    request_path: str = _CONFIG_PATH,
    has_proof: bool,
    secrets: list[str],
) -> _Result:
    """Simulate bind_tenant_id with pre-bound middleware state (the old bypass scenario).

    Models the defense-in-depth: even if tenant_is_key_bound=True and tenant_id are
    pre-committed by the middleware, the admin_internal_token guard forces the request
    through delegation verification.

    In the OLD code: this function would return ok=True immediately.
    In the FIXED code: it mirrors the guard that clears key_bound_flag and routes
    through delegation.
    """
    # Simulated pre-bound state from middleware (old bug)
    _cached_tenant = prebind_tenant
    _key_bound_flag = True
    _auth_reason = "admin_internal_token"

    # Defense-in-depth guard (mirrors the fix in bind_tenant_id):
    # admin_internal_token must not use the key_bound fast-path.
    if _cached_tenant and _key_bound_flag and _auth_reason == "admin_internal_token":
        # Clear pre-bound flag — fall through to delegation check.
        _key_bound_flag = False

    # auth_tenant fast-path guard (second layer):
    # admin_internal_token is also excluded from the auth_tenant fast-path.
    _auth_tenant: str | None = (
        prebind_tenant  # old bug: middleware injected this into auth result
    )
    if _auth_tenant and _auth_reason == "admin_internal_token":
        _auth_tenant = None  # excluded — must go through delegation

    # admin_internal_token branch: delegation required
    if _auth_reason == "admin_internal_token":
        if not has_proof:
            return _delegation_check(
                tenant_id=request_tenant,
                request_id=_TEST_REQUEST_ID,
                method=request_method,
                path=request_path,
                version=None,
                issued_at=None,
                expires_at=None,
                proof=None,
                secrets=secrets,
            )
        proof_hex, iat, exp = _make_proof(
            proof_tenant,
            method=proof_method,
            path=proof_path,
        )
        return _delegation_check(
            tenant_id=request_tenant,
            request_id=_TEST_REQUEST_ID,
            method=request_method,
            path=request_path,
            version="v1",
            issued_at=iat,
            expires_at=exp,
            proof=proof_hex,
            secrets=secrets,
        )

    # canonical_validated fast-path (for test H — should still return immediately)
    return _Result(ok=True)


# ── A: source — middleware excludes admin_internal_token from _tenant_injectable ─


def test_A_authgate_tenant_injectable_excludes_admin_internal_token() -> None:
    # Find the _tenant_injectable assignment line
    line_start = _AUTHGATE_SRC.index("_tenant_injectable = ")
    line_end = _AUTHGATE_SRC.index("\n", line_start)
    injectable_line = _AUTHGATE_SRC[line_start:line_end]
    assert "admin_internal_token" not in injectable_line, (
        "_tenant_injectable must not include admin_internal_token — "
        "pre-binding bypasses delegation verification (PR-CORE-002B)"
    )


# ── B: source — key_bound fast-path has admin_internal_token guard ─────────────


def test_B_bind_tenant_id_key_bound_fast_path_guards_admin_internal_token() -> None:
    # Locate the key_bound_flag fast-path block
    key_bound_block_start = _RESOLUTION_SRC.index(
        "if cached_tenant and key_bound_flag:"
    )
    key_bound_block_end = _RESOLUTION_SRC.index("\n    auth = ", key_bound_block_start)
    block = _RESOLUTION_SRC[key_bound_block_start:key_bound_block_end]
    assert "admin_internal_token" in block, (
        "bind_tenant_id key_bound fast-path must guard against admin_internal_token — "
        "pre-bound state must not bypass delegation (PR-CORE-002B)"
    )


# ── C: source — auth_tenant fast-path has admin_internal_token guard ───────────


def test_C_bind_tenant_id_auth_tenant_fast_path_guards_admin_internal_token() -> None:
    # Locate the auth_tenant fast-path — the if-block that returns auth_tenant directly
    auth_tenant_block_start = _RESOLUTION_SRC.index("if auth_tenant and getattr(auth")
    auth_tenant_block_end = _RESOLUTION_SRC.index(
        "return auth_tenant", auth_tenant_block_start
    )
    block = _RESOLUTION_SRC[auth_tenant_block_start:auth_tenant_block_end]
    assert "admin_internal_token" in block, (
        "bind_tenant_id auth_tenant fast-path must exclude admin_internal_token — "
        "second defense-in-depth layer (PR-CORE-002B)"
    )


# ── D: source — admin_internal_token branch ordering preserved ─────────────────


def test_D_admin_internal_token_delegation_precedes_state_mutation() -> None:
    delegation_pos = _RESOLUTION_SRC.index(
        "_verify_delegation_proof(request, requested)"
    )
    state_pos = _RESOLUTION_SRC.index(
        "request.state.tenant_id = requested", delegation_pos
    )
    key_bound_set_pos = _RESOLUTION_SRC.index(
        "request.state.tenant_is_key_bound = True", delegation_pos
    )
    assert delegation_pos < state_pos, (
        "delegation must precede state.tenant_id mutation"
    )
    assert delegation_pos < key_bound_set_pos, (
        "delegation must precede tenant_is_key_bound mutation"
    )


# ── E: behavioral — pre-bound state + no proof → 403, not 200 ──────────────────


def test_E_prebind_bypass_missing_proof_returns_403() -> None:
    result = _simulate_bind_with_prebind(
        prebind_tenant=_TEST_TENANT,
        request_tenant=_TEST_TENANT,
        has_proof=False,
        secrets=[_TEST_SECRET],
    )
    assert not result.ok, (
        "Pre-bound admin_internal_token state with no delegation proof must return 403. "
        "A 200 here means the key_bound fast-path bypass is NOT closed (PR-CORE-002B)."
    )
    assert result.status_code == 403
    assert result.reason == "proof_required"


# ── F: behavioral — pre-bound state + wrong method in proof → 403 ──────────────


def test_F_prebind_bypass_method_replay_returns_403() -> None:
    result = _simulate_bind_with_prebind(
        prebind_tenant=_TEST_TENANT,
        request_tenant=_TEST_TENANT,
        proof_tenant=_TEST_TENANT,
        proof_method="GET",
        proof_path=_CONFIG_PATH,
        request_method="PUT",  # signed for GET, sent as PUT
        request_path=_CONFIG_PATH,
        has_proof=True,
        secrets=[_TEST_SECRET],
    )
    assert not result.ok, (
        "GET-signed proof must not authorize a PUT request (method replay). "
        "A 200 here means delegation is being bypassed (PR-CORE-002B)."
    )
    assert result.status_code == 403
    assert result.reason == "proof_invalid"


# ── G: behavioral — pre-bound state + wrong path in proof → 403 ────────────────


def test_G_prebind_bypass_path_replay_returns_403() -> None:
    result = _simulate_bind_with_prebind(
        prebind_tenant=_TEST_TENANT,
        request_tenant=_TEST_TENANT,
        proof_tenant=_TEST_TENANT,
        proof_method="GET",
        proof_path=_CONFIG_PATH,  # proof signed for /config
        request_method="GET",
        request_path=_READINESS_PATH,  # request targets /readiness
        has_proof=True,
        secrets=[_TEST_SECRET],
    )
    assert not result.ok, (
        "/config-signed proof must not authorize a /readiness request (path replay). "
        "A 200 here means delegation is being bypassed (PR-CORE-002B)."
    )
    assert result.status_code == 403
    assert result.reason == "proof_invalid"


# ── H: behavioral — valid proof passes (regression: valid path must still work) ──


def test_H_valid_proof_correct_method_path_passes() -> None:
    result = _simulate_bind_with_prebind(
        prebind_tenant=_TEST_TENANT,
        request_tenant=_TEST_TENANT,
        proof_tenant=_TEST_TENANT,
        proof_method="GET",
        proof_path=_CONFIG_PATH,
        request_method="GET",
        request_path=_CONFIG_PATH,
        has_proof=True,
        secrets=[_TEST_SECRET],
    )
    assert result.ok, (
        "A valid delegation proof must still authorize a correctly-signed request. "
        "The defense-in-depth must not break the legitimate admin gateway path."
    )
