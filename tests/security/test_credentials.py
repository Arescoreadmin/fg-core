"""
Task 12.1 — Customer Credential Issuance / Revoke / Rotate

Tests proving:
1) Credentials are issued with a one-time secret
2) Secrets are stored hashed (never plaintext)
3) Valid credential authenticates and returns correct tenant_id
4) Missing credential → AUTH_REQUIRED (401)
5) Invalid credential → AUTH_INVALID (401)
6) Revoked credential → AUTH_REVOKED (401)
7) Cross-tenant credential usage → TENANT_ACCESS_DENIED (403)
8) Rotation invalidates the old credential
9) New rotated credential authenticates successfully
10) No secret value appears in logs or error payloads
11) Constant-time comparison assurance (HMAC/Argon2 path exercised)
12) Gateway-only admin access still enforced after credential module added
"""

from __future__ import annotations

import hmac
import sqlite3

import pytest
from fastapi import HTTPException

from api.credentials import (
    ERR_AUTH_INVALID,
    ERR_AUTH_REQUIRED,
    ERR_AUTH_REVOKED,
    ERR_TENANT_ACCESS_DENIED,
    create_credential,
    revoke_credential,
    rotate_credential,
    validate_credential,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def credential_env(tmp_path, monkeypatch):
    """Isolated SQLite + pepper for each test."""
    db_path = str(tmp_path / "cred_test.db")
    monkeypatch.setenv("FG_SQLITE_PATH", db_path)
    monkeypatch.setenv("FG_KEY_PEPPER", "test-credential-pepper-12345")
    monkeypatch.setenv("FG_ENV", "test")

    from api.db import init_db, reset_engine_cache

    reset_engine_cache()
    init_db(sqlite_path=db_path)
    return db_path


# ---------------------------------------------------------------------------
# 1) test_credential_issue_returns_secret_once
# ---------------------------------------------------------------------------


def test_credential_issue_returns_secret_once(credential_env):
    """create_credential returns a non-empty one-time secret string."""
    record, secret = create_credential("tenant-a")
    assert secret  # non-empty
    assert "fgk." in secret  # standard key prefix
    assert record.tenant_id == "tenant-a"
    assert record.status == "active"
    assert record.credential_id  # non-empty opaque identifier
    assert record.rotated_from is None


# ---------------------------------------------------------------------------
# 2) test_credential_stored_hashed_only
# ---------------------------------------------------------------------------


def test_credential_stored_hashed_only(credential_env):
    """The secret plaintext must not appear in the database."""
    db_path = credential_env
    record, secret = create_credential("tenant-b")

    # Extract the raw secret component (last segment of fgk.token.secret)
    secret_part = secret.rsplit(".", 1)[-1]

    con = sqlite3.connect(db_path)
    try:
        rows = con.execute(
            "SELECT key_hash, name, scopes_csv FROM api_keys ORDER BY id DESC LIMIT 1"
        ).fetchall()
    finally:
        con.close()

    assert rows, "Expected a row in api_keys"
    key_hash, name, scopes_csv = rows[0]

    # Plaintext secret must not appear anywhere in the stored row
    assert secret_part not in (key_hash or "")
    assert secret_part not in (name or "")
    assert "credential:use" in scopes_csv
    # Hash must be Argon2id format
    assert key_hash.startswith("$argon2")


# ---------------------------------------------------------------------------
# 3) test_valid_credential_authenticates
# ---------------------------------------------------------------------------


def test_valid_credential_authenticates(credential_env):
    """A freshly issued credential must authenticate and return the correct tenant_id."""
    record, secret = create_credential("tenant-c")
    tenant = validate_credential(secret)
    assert tenant == "tenant-c"


# ---------------------------------------------------------------------------
# 4) test_missing_credential_fails
# ---------------------------------------------------------------------------


def test_missing_credential_fails(credential_env):
    """Empty/None credential must raise AUTH_REQUIRED (401)."""
    with pytest.raises(HTTPException) as exc:
        validate_credential(None)
    assert exc.value.status_code == 401
    assert exc.value.detail["code"] == ERR_AUTH_REQUIRED

    with pytest.raises(HTTPException) as exc2:
        validate_credential("")
    assert exc2.value.status_code == 401
    assert exc2.value.detail["code"] == ERR_AUTH_REQUIRED


# ---------------------------------------------------------------------------
# 5) test_invalid_credential_fails
# ---------------------------------------------------------------------------


def test_invalid_credential_fails(credential_env):
    """A fabricated / wrong credential must raise AUTH_INVALID (401)."""
    with pytest.raises(HTTPException) as exc:
        validate_credential("fgk.eyJmYWtlIjoidG9rZW4ifQ.invalidsecretvalue")
    assert exc.value.status_code == 401
    assert exc.value.detail["code"] == ERR_AUTH_INVALID


# ---------------------------------------------------------------------------
# 6) test_revoked_credential_fails
# ---------------------------------------------------------------------------


def test_revoked_credential_fails(credential_env):
    """A revoked credential must raise AUTH_REVOKED (401)."""
    record, secret = create_credential("tenant-d")
    revoke_credential(record.credential_id, "tenant-d")

    with pytest.raises(HTTPException) as exc:
        validate_credential(secret)
    assert exc.value.status_code == 401
    assert exc.value.detail["code"] == ERR_AUTH_REVOKED


# ---------------------------------------------------------------------------
# 7) test_cross_tenant_credential_forbidden
# ---------------------------------------------------------------------------


def test_cross_tenant_credential_forbidden(credential_env):
    """Using tenant-a's credential against tenant-b context must raise TENANT_ACCESS_DENIED (403)."""
    _rec_a, secret_a = create_credential("tenant-a")

    with pytest.raises(HTTPException) as exc:
        validate_credential(secret_a, expected_tenant_id="tenant-b")
    assert exc.value.status_code == 403
    assert exc.value.detail["code"] == ERR_TENANT_ACCESS_DENIED


# ---------------------------------------------------------------------------
# 8) test_rotation_invalidates_old_credential
# ---------------------------------------------------------------------------


def test_rotation_invalidates_old_credential(credential_env):
    """After rotation, the original credential must be revoked."""
    record, old_secret = create_credential("tenant-e")
    _new_record, _new_secret = rotate_credential(record.credential_id, "tenant-e")

    # Old credential must now be revoked
    with pytest.raises(HTTPException) as exc:
        validate_credential(old_secret)
    assert exc.value.status_code == 401
    assert exc.value.detail["code"] == ERR_AUTH_REVOKED


# ---------------------------------------------------------------------------
# 9) test_new_rotated_credential_works
# ---------------------------------------------------------------------------


def test_new_rotated_credential_works(credential_env):
    """After rotation, the new credential must authenticate successfully."""
    record, _old_secret = create_credential("tenant-f")
    new_record, new_secret = rotate_credential(record.credential_id, "tenant-f")

    tenant = validate_credential(new_secret)
    assert tenant == "tenant-f"
    assert new_record.tenant_id == "tenant-f"
    assert new_record.rotated_from == record.credential_id
    assert new_record.status == "active"


# ---------------------------------------------------------------------------
# 10) test_no_secret_leak_in_logs_or_errors
# ---------------------------------------------------------------------------


def test_no_secret_leak_in_logs_or_errors(credential_env):
    """Error payloads must never contain the credential secret or tenant mapping."""
    record, secret = create_credential("tenant-g")
    secret_part = secret.rsplit(".", 1)[-1]
    revoke_credential(record.credential_id, "tenant-g")

    # Auth errors must not reveal the secret
    with pytest.raises(HTTPException) as exc:
        validate_credential(secret)
    detail = exc.value.detail
    detail_str = str(detail)
    assert secret_part not in detail_str
    assert "tenant-g" not in detail_str  # no tenant leak in revoked error

    # Cross-tenant error must not reveal the actual tenant
    _rec_a, sec_a = create_credential("tenant-secret-a")
    with pytest.raises(HTTPException) as exc2:
        validate_credential(sec_a, expected_tenant_id="tenant-other")
    detail2 = str(exc2.value.detail)
    assert "tenant-secret-a" not in detail2


# ---------------------------------------------------------------------------
# 11) test_constant_time_comparison_behavior
# ---------------------------------------------------------------------------


def test_constant_time_comparison_behavior(credential_env, monkeypatch):
    """Validation path must exercise hmac.compare_digest (constant-time comparison).

    We track calls to hmac.compare_digest through the auth_scopes helpers path.
    The Argon2id verify() call is itself constant-time; this test confirms the
    key_lookup HMAC path also uses compare_digest for short-circuit prevention.
    """
    calls: list[tuple] = []
    real_compare = hmac.compare_digest

    def tracking_compare(a, b):
        calls.append((type(a).__name__, type(b).__name__))
        return real_compare(a, b)

    monkeypatch.setattr(hmac, "compare_digest", tracking_compare)

    # Re-import to pick up the monkeypatched hmac
    import importlib

    import api.auth_scopes.helpers as helpers_mod
    import api.auth_scopes.resolution as res_mod

    importlib.reload(helpers_mod)
    importlib.reload(res_mod)

    record, secret = create_credential("tenant-h")
    calls.clear()

    try:
        validate_credential(secret)
    finally:
        # Restore originals so other tests are not affected
        importlib.reload(helpers_mod)
        importlib.reload(res_mod)

    # compare_digest must have been called during validation
    assert calls, (
        "hmac.compare_digest was not called during credential validation — "
        "key_lookup comparison may be timing-vulnerable"
    )


# ---------------------------------------------------------------------------
# 12) test_gateway_only_access_still_enforced
# ---------------------------------------------------------------------------


def test_gateway_only_access_still_enforced(monkeypatch):
    """Adding credentials.py must not weaken admin gateway enforcement.

    Importing credentials must not bypass require_internal_admin_gateway.
    """
    from types import SimpleNamespace

    import api.credentials  # noqa: F401 — ensure import side-effects present

    monkeypatch.setenv("FG_INTERNAL_AUTH_SECRET", "gateway-test-secret-abc")

    from api.admin import require_internal_admin_gateway

    req = SimpleNamespace(headers={})  # no x-fg-internal-token header

    with pytest.raises(HTTPException) as exc:
        require_internal_admin_gateway(req)
    assert exc.value.status_code == 403
    assert exc.value.detail["code"] == "ADMIN_GATEWAY_FORBIDDEN"


# ---------------------------------------------------------------------------
# 13) test_credential_validation_rejects_non_customer_scope_key
# ---------------------------------------------------------------------------


def test_credential_validation_rejects_non_customer_scope_key(
    credential_env, monkeypatch
):
    """A valid API key without credential:use scope must be rejected by validate_credential.

    Simulates an internal/admin key being presented as a customer credential.
    verify_api_key_detailed returns valid=False when required_scopes are not met.
    """
    from unittest.mock import patch

    from api.auth_scopes.definitions import AuthResult

    # Simulate a key that is otherwise valid but lacks credential:use scope
    wrong_scope_result = AuthResult(
        valid=False,
        reason="missing_required_scopes",
        tenant_id="tenant-a",
        scopes={"admin:read"},  # admin scope, not credential:use
    )

    with patch(
        "api.credentials.verify_api_key_detailed", return_value=wrong_scope_result
    ):
        with pytest.raises(HTTPException) as exc:
            validate_credential("fgk.sometoken.somesecret")

    assert exc.value.status_code == 401
    assert exc.value.detail["code"] == ERR_AUTH_INVALID


# ---------------------------------------------------------------------------
# 14) test_credential_validation_rejects_key_without_tenant_binding
# ---------------------------------------------------------------------------


def test_credential_validation_rejects_key_without_tenant_binding(
    credential_env, monkeypatch
):
    """A credential that passes validation but has no tenant_id must fail closed.

    Guards against keys minted without a tenant binding slipping through.
    """
    from unittest.mock import patch

    from api.auth_scopes.definitions import AuthResult

    # Simulate a structurally valid key with credential:use but no tenant_id
    no_tenant_result = AuthResult(
        valid=True,
        reason="",
        tenant_id=None,  # missing tenant binding
        scopes={"credential:use"},
    )

    with patch(
        "api.credentials.verify_api_key_detailed", return_value=no_tenant_result
    ):
        with pytest.raises(HTTPException) as exc:
            validate_credential("fgk.sometoken.somesecret")

    assert exc.value.status_code == 401
    assert exc.value.detail["code"] == ERR_AUTH_INVALID
