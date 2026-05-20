"""Tests for TenantLock tenant isolation enforcement."""

from __future__ import annotations

import pytest

from services.connectors.msgraph.manifest import TenantIsolationError
from services.connectors.msgraph.tenant import TenantLock, hash_tenant_id


_TENANT_ID = "11111111-2222-3333-4444-555555555555"
_OTHER_TENANT = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"


def _ctx_url(tid: str) -> str:
    return f"https://graph.microsoft.com/v1.0/$metadata#users(id,displayName)?$skip=0&tenantId={tid}"


def test_validate_passes_when_no_context_key():
    with TenantLock(_TENANT_ID) as lock:
        lock.validate_response({"value": []})  # no @odata.context


def test_validate_passes_when_tenant_matches():
    with TenantLock(_TENANT_ID) as lock:
        lock.validate_response({"@odata.context": _ctx_url(_TENANT_ID)})


def test_validate_rejects_mismatched_tenant():
    with TenantLock(_TENANT_ID) as lock:
        with pytest.raises(TenantIsolationError):
            lock.validate_response({"@odata.context": _ctx_url(_OTHER_TENANT)})


def test_validate_passes_on_generic_metadata_url():
    with TenantLock(_TENANT_ID) as lock:
        # URL with no UUID — generic metadata endpoint
        lock.validate_response(
            {"@odata.context": "https://graph.microsoft.com/v1.0/$metadata#users"}
        )


def test_validate_outside_context_raises():
    lock = TenantLock(_TENANT_ID)
    with pytest.raises(RuntimeError, match="outside context"):
        lock.validate_response({})


def test_hash_tenant_id_is_sha256():
    import hashlib

    tid = "my-tenant"
    assert hash_tenant_id(tid) == hashlib.sha256(tid.encode()).hexdigest()
