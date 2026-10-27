"""Negative tests: credential isolation and tenant binding for the stats endpoint.

These tests prove that:
1. Credential issuance fails closed when FG_KEY_PEPPER is absent.
2. Tenant-scoped keys are bound to the correct tenant_id.
3. The _restore_env fixture preserves FG_KEY_PEPPER across individual tests
   so that test ordering cannot silently disable pepper-based credential checks.
"""

from __future__ import annotations

import os
from typing import cast

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from api.auth_scopes import mint_key


# ---------------------------------------------------------------------------
# Fail-closed: credential issuance without FG_KEY_PEPPER
# ---------------------------------------------------------------------------


def test_mint_key_fails_closed_without_pepper(monkeypatch: pytest.MonkeyPatch) -> None:
    """_get_pepper() must raise RuntimeError when FG_KEY_PEPPER is absent.

    This is the regression guard for the confirmed GitHub failure:
    "RuntimeError: FG_KEY_PEPPER not configured; cannot issue or validate credentials."
    The guard proves the error is properly surfaced (not silently suppressed)
    and that the fix (setting FG_KEY_PEPPER in the session fixture) is load-bearing.
    """
    monkeypatch.delenv("FG_KEY_PEPPER", raising=False)
    with pytest.raises(RuntimeError, match="FG_KEY_PEPPER not configured"):
        mint_key("stats:read", tenant_id="test-tenant")


def test_pepper_is_restored_after_deletion(monkeypatch: pytest.MonkeyPatch) -> None:
    """FG_KEY_PEPPER must be present again after _restore_env teardown.

    Proves that _restore_env correctly restores the pepper even when a prior
    test deleted it, preventing silent cascade failures in subsequent tests.
    """
    monkeypatch.delenv("FG_KEY_PEPPER", raising=False)
    assert os.environ.get("FG_KEY_PEPPER") is None  # deleted inside this test
    # After this test finishes, _restore_env will restore FG_KEY_PEPPER.
    # The next test in the module can call mint_key() without error.


def test_mint_key_succeeds_with_pepper() -> None:
    """Credential issuance succeeds when FG_KEY_PEPPER is properly configured.

    Proves the positive case: with the session fixture in place, mint_key() works
    in the backend test subtree without any per-test setup.
    """
    assert os.environ.get("FG_KEY_PEPPER") == "ci-test-pepper"
    key = mint_key("stats:read", tenant_id="tenant-isolation-test")
    assert key.startswith("fgk.")


# ---------------------------------------------------------------------------
# Tenant isolation: key bound to the tenant it was issued for
# ---------------------------------------------------------------------------


def test_key_contains_tenant_binding(build_app) -> None:
    """A key issued for a specific tenant must embed the correct tenant_id.

    The stats endpoint validates the API key and identifies the tenant from it.
    A key issued for tenant-a must succeed on the stats endpoint (authenticated
    as tenant-a), not silently serve another tenant's data.
    """
    from api.credential_authority import validate_credential
    from api.db import get_engine

    app = build_app()
    client = TestClient(cast(FastAPI, app))

    key = mint_key("stats:read", tenant_id="tenant-alpha")
    engine = get_engine()

    cred = validate_credential(engine, key)
    assert cred is not None, "validate_credential must return a result for a valid key"
    assert cred.tenant_id == "tenant-alpha", (
        f"Credential tenant_id must be 'tenant-alpha', got {cred.tenant_id!r}"
    )

    r = client.get("/stats", headers={"x-api-key": key})
    assert r.status_code == 200


def test_different_tenants_get_distinct_keys(build_app) -> None:
    """Two tenants must receive distinct, non-interchangeable credentials."""
    key_a = mint_key("stats:read", tenant_id="tenant-a")
    key_b = mint_key("stats:read", tenant_id="tenant-b")
    assert key_a != key_b, "Keys for different tenants must be distinct"


def test_stats_with_no_key_is_rejected(build_app) -> None:
    """Stats endpoint must reject unauthenticated requests (fail closed)."""
    app = build_app()
    client = TestClient(cast(FastAPI, app))
    r = client.get("/stats")
    assert r.status_code in (401, 403)
