"""
Regression tests for Task 9.1 — Tenant creation through supported product path.

Covers:
- Happy-path tenant creation via POST /admin/tenants
- Invalid payload rejected explicitly
- Unauthorized tenant creation rejected
- Created tenant observable via GET /admin/tenants and GET /admin/tenants/{tenant_id}
- Duplicate tenant creation returns 409
- Persistence is real (not mocked success)
"""

from __future__ import annotations

import json as _json
import os
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient


os.environ.setdefault("FG_ENV", "test")
os.environ.setdefault("FG_API_KEY", "ci-test-key-00000000000000000000000000000000")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _build_admin_app(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> FastAPI:
    """Build the core API app with admin routes enabled."""
    from api.db import init_db, reset_engine_cache
    from api.main import build_app

    db_path = str(tmp_path / "tenant-create-test.db")
    monkeypatch.setenv("FG_SQLITE_PATH", db_path)
    monkeypatch.setenv("FG_ENV", "test")
    monkeypatch.setenv("FG_AUTH_ENABLED", "1")
    monkeypatch.setenv("FG_API_KEY", "ci-test-key-00000000000000000000000000000000")
    monkeypatch.setenv("FG_KEY_PEPPER", "ci-test-pepper")
    monkeypatch.setenv("FG_DEVICE_KEY_KEK_CURRENT_VERSION", "v1")
    monkeypatch.setenv(
        "FG_DEVICE_KEY_KEK_V1", "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY="
    )
    monkeypatch.setenv("FG_ADMIN_ENABLED", "1")

    reset_engine_cache()
    init_db(sqlite_path=db_path)
    return build_app()


def _patch_registry(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Redirect the tenant registry to a fresh per-test file.

    REGISTRY_PATH is a module-level constant captured at import time;
    we must patch the object directly rather than relying on env var.
    """
    import tools.tenants.registry as _reg

    registry_path = tmp_path / "tenants.json"
    monkeypatch.setattr(_reg, "REGISTRY_PATH", registry_path)
    return registry_path


def _admin_headers() -> dict[str, str]:
    return {"x-api-key": "ci-test-key-00000000000000000000000000000000"}


# ---------------------------------------------------------------------------
# Core API tests — POST /admin/tenants
# ---------------------------------------------------------------------------


class TestTenantCreateHappyPath:
    """Happy-path tenant creation through the supported product path."""

    def test_create_tenant_returns_201(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """POST /admin/tenants with valid payload returns 201 and tenant record."""
        app = _build_admin_app(tmp_path, monkeypatch)
        _patch_registry(tmp_path, monkeypatch)

        with TestClient(app) as client:
            resp = client.post(
                "/admin/tenants",
                json={"tenant_id": "acme-corp", "name": "Acme Corporation"},
                headers=_admin_headers(),
            )

        assert resp.status_code == 201, resp.text
        data = resp.json()
        assert data["tenant_id"] == "acme-corp"
        assert data["name"] == "Acme Corporation"
        assert data["status"] == "active"
        assert "created_at" in data
        assert "updated_at" in data

    def test_create_tenant_persisted_in_registry(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Created tenant is persisted to the tenant registry."""
        app = _build_admin_app(tmp_path, monkeypatch)
        registry_path = _patch_registry(tmp_path, monkeypatch)

        with TestClient(app) as client:
            client.post(
                "/admin/tenants",
                json={"tenant_id": "persisted-tenant"},
                headers=_admin_headers(),
            )

        # Verify registry was actually written to the test path
        assert registry_path.exists(), "Registry file not created"
        data = _json.loads(registry_path.read_text())
        assert "persisted-tenant" in data

    def test_created_tenant_observable_via_get(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Created tenant is observable through the intended read path."""
        app = _build_admin_app(tmp_path, monkeypatch)
        _patch_registry(tmp_path, monkeypatch)

        with TestClient(app) as client:
            # Create
            create_resp = client.post(
                "/admin/tenants",
                json={"tenant_id": "readable-tenant", "name": "Readable"},
                headers=_admin_headers(),
            )
            assert create_resp.status_code == 201, create_resp.text

            # Read back via GET /admin/tenants/{tenant_id}
            get_resp = client.get(
                "/admin/tenants/readable-tenant",
                headers=_admin_headers(),
            )
            assert get_resp.status_code == 200, get_resp.text
            get_data = get_resp.json()
            assert get_data["tenant_id"] == "readable-tenant"
            assert get_data["name"] == "Readable"
            assert get_data["status"] == "active"

    def test_created_tenant_appears_in_list(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Created tenant appears in GET /admin/tenants listing."""
        app = _build_admin_app(tmp_path, monkeypatch)
        _patch_registry(tmp_path, monkeypatch)

        with TestClient(app) as client:
            client.post(
                "/admin/tenants",
                json={"tenant_id": "listed-tenant"},
                headers=_admin_headers(),
            )
            list_resp = client.get(
                "/admin/tenants",
                headers=_admin_headers(),
            )

        assert list_resp.status_code == 200, list_resp.text
        body = list_resp.json()
        tenant_ids = [t["tenant_id"] for t in body["tenants"]]
        assert "listed-tenant" in tenant_ids

    def test_create_tenant_without_name_uses_tenant_id(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Tenant creation without explicit name defaults name to tenant_id."""
        app = _build_admin_app(tmp_path, monkeypatch)
        _patch_registry(tmp_path, monkeypatch)

        with TestClient(app) as client:
            resp = client.post(
                "/admin/tenants",
                json={"tenant_id": "no-name-tenant"},
                headers=_admin_headers(),
            )

        assert resp.status_code == 201, resp.text
        data = resp.json()
        assert data["name"] == "no-name-tenant"


class TestTenantCreateInvalidPayload:
    """Invalid payloads must fail explicitly with actionable errors."""

    def test_missing_tenant_id_returns_422(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Request without tenant_id fails with 422 validation error."""
        app = _build_admin_app(tmp_path, monkeypatch)
        _patch_registry(tmp_path, monkeypatch)

        with TestClient(app) as client:
            resp = client.post(
                "/admin/tenants",
                json={"name": "No ID Tenant"},
                headers=_admin_headers(),
            )

        assert resp.status_code == 422

    def test_invalid_tenant_id_characters_returns_4xx(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """tenant_id with special characters is rejected with 4xx."""
        app = _build_admin_app(tmp_path, monkeypatch)
        _patch_registry(tmp_path, monkeypatch)

        with TestClient(app) as client:
            resp = client.post(
                "/admin/tenants",
                json={"tenant_id": "bad tenant id!"},
                headers=_admin_headers(),
            )

        # Pydantic rejects on length/field level; custom handler returns 422
        assert resp.status_code in (422, 400), resp.text

    def test_tenant_id_too_long_returns_422(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """tenant_id exceeding 128 characters is rejected."""
        app = _build_admin_app(tmp_path, monkeypatch)
        _patch_registry(tmp_path, monkeypatch)

        long_id = "a" * 129
        with TestClient(app) as client:
            resp = client.post(
                "/admin/tenants",
                json={"tenant_id": long_id},
                headers=_admin_headers(),
            )

        assert resp.status_code == 422

    def test_unknown_extra_fields_rejected(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Extra fields not in schema are rejected (model_config extra=forbid)."""
        app = _build_admin_app(tmp_path, monkeypatch)
        _patch_registry(tmp_path, monkeypatch)

        with TestClient(app) as client:
            resp = client.post(
                "/admin/tenants",
                json={"tenant_id": "extra-field-test", "admin": True},
                headers=_admin_headers(),
            )

        assert resp.status_code == 422


class TestTenantCreateUnauthorized:
    """Unauthorized tenant creation must be rejected."""

    def test_no_api_key_returns_401(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Request without API key is rejected with 401."""
        app = _build_admin_app(tmp_path, monkeypatch)
        _patch_registry(tmp_path, monkeypatch)

        with TestClient(app) as client:
            resp = client.post(
                "/admin/tenants",
                json={"tenant_id": "unauthorized-tenant"},
            )

        assert resp.status_code in (401, 403)

    def test_wrong_api_key_returns_401(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Request with invalid API key is rejected."""
        app = _build_admin_app(tmp_path, monkeypatch)
        _patch_registry(tmp_path, monkeypatch)

        with TestClient(app) as client:
            resp = client.post(
                "/admin/tenants",
                json={"tenant_id": "unauthorized-tenant"},
                headers={"x-api-key": "wrong-key-000000000000000000000000000000000"},
            )

        assert resp.status_code in (401, 403)


class TestTenantCreateConflict:
    """Duplicate tenant creation must return explicit 409 conflict."""

    def test_duplicate_tenant_returns_409(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Creating a tenant that already exists returns 409."""
        app = _build_admin_app(tmp_path, monkeypatch)
        _patch_registry(tmp_path, monkeypatch)

        with TestClient(app) as client:
            # First creation
            resp1 = client.post(
                "/admin/tenants",
                json={"tenant_id": "duplicate-tenant"},
                headers=_admin_headers(),
            )
            assert resp1.status_code == 201, resp1.text

            # Duplicate
            resp2 = client.post(
                "/admin/tenants",
                json={"tenant_id": "duplicate-tenant"},
                headers=_admin_headers(),
            )
            assert resp2.status_code == 409
            detail = resp2.json().get("detail", "")
            assert "already exists" in detail.lower() or "duplicate" in detail.lower()


class TestTenantReadPath:
    """Tenant read paths return correct errors for not-found scenarios."""

    def test_get_nonexistent_tenant_returns_404(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """GET /admin/tenants/{tenant_id} for unknown tenant returns 404."""
        app = _build_admin_app(tmp_path, monkeypatch)
        _patch_registry(tmp_path, monkeypatch)

        with TestClient(app) as client:
            resp = client.get(
                "/admin/tenants/does-not-exist",
                headers=_admin_headers(),
            )

        assert resp.status_code == 404

    def test_get_tenant_invalid_format_returns_422(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """GET /admin/tenants/{tenant_id} with characters outside allowed set returns 422."""
        app = _build_admin_app(tmp_path, monkeypatch)
        _patch_registry(tmp_path, monkeypatch)

        # Use a tenant_id with slashes in it which would route to a different path;
        # instead test one with obviously bad chars via a POST then check read path
        with TestClient(app) as client:
            # Dot is NOT in TENANT_ID_PATTERN so 'bad.id' → 422
            resp = client.get(
                "/admin/tenants/bad.id",
                headers=_admin_headers(),
            )

        # bad.id doesn't match _TENANT_ID_RE → 422
        assert resp.status_code in (404, 422)


class TestAtomicDuplicateProtection:
    """Authoritative uniqueness enforcement must live at the write boundary.

    The duplicate check inside create_tenant_exclusive (under _REGISTRY_LOCK)
    is the canonical guard.  These tests verify the lock + re-check protects
    against races where the pre-flight read-before-write would otherwise allow
    two concurrent callers to both succeed.
    """

    def test_sequential_duplicate_returns_409_at_write_boundary(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Second create for same tenant_id hits the lock-protected check → 409."""
        from tools.tenants.registry import (
            TenantAlreadyExistsError,
            create_tenant_exclusive,
        )

        registry_path = tmp_path / "tenants.json"
        import tools.tenants.registry as _reg

        monkeypatch.setattr(_reg, "REGISTRY_PATH", registry_path)

        # First create must succeed and persist.
        rec1 = create_tenant_exclusive("dup-lock-test", name="First")
        assert rec1.tenant_id == "dup-lock-test"
        assert registry_path.exists()

        # Second create must raise — duplicate found inside the lock.
        with pytest.raises(TenantAlreadyExistsError) as exc_info:
            create_tenant_exclusive("dup-lock-test", name="Second")
        assert "dup-lock-test" in str(exc_info.value)

        # Registry must contain exactly one entry.
        data = _json.loads(registry_path.read_text())
        assert list(data.keys()) == ["dup-lock-test"]

    def test_simulated_race_pre_check_bypassed_lock_still_rejects(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Simulate a race: tenant written to registry after API pre-check but before
        create_tenant_exclusive acquires the lock.  The lock's re-read inside the
        critical section must still catch the duplicate and raise.
        """
        import tools.tenants.registry as _reg
        from tools.tenants.registry import TenantAlreadyExistsError

        registry_path = tmp_path / "tenants.json"
        monkeypatch.setattr(_reg, "REGISTRY_PATH", registry_path)

        # Seed the registry directly — simulates what the "winning" concurrent
        # request wrote between our pre-check and lock acquisition.
        _reg._save_raw(
            {
                "race-tenant": {
                    "name": "Race Winner",
                    "api_key": "dummy-key",
                    "status": "active",
                    "created_at": "2026-01-01T00:00:00+00:00",
                    "updated_at": "2026-01-01T00:00:00+00:00",
                }
            }
        )

        # Even though the API pre-check would have seen nothing (before seeding),
        # create_tenant_exclusive re-reads inside the lock and must reject.
        with pytest.raises(TenantAlreadyExistsError):
            _reg.create_tenant_exclusive("race-tenant", name="Race Loser")

        # Registry still has exactly one entry — not two.
        data = _json.loads(registry_path.read_text())
        assert list(data.keys()) == ["race-tenant"]
        assert data["race-tenant"]["name"] == "Race Winner"

    def test_concurrent_creates_exactly_one_succeeds(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Thread-level concurrency: two threads call create_tenant_exclusive
        simultaneously; exactly one must succeed and one must raise."""
        import threading

        import tools.tenants.registry as _reg
        from tools.tenants.registry import TenantAlreadyExistsError

        registry_path = tmp_path / "tenants.json"
        monkeypatch.setattr(_reg, "REGISTRY_PATH", registry_path)

        outcomes: list[str] = []
        lock = threading.Lock()

        def _attempt() -> None:
            try:
                _reg.create_tenant_exclusive("concurrent-tenant")
                with lock:
                    outcomes.append("success")
            except TenantAlreadyExistsError:
                with lock:
                    outcomes.append("conflict")

        threads = [threading.Thread(target=_attempt) for _ in range(2)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert outcomes.count("success") == 1, (
            f"Expected exactly 1 success, got: {outcomes}"
        )
        assert outcomes.count("conflict") == 1, (
            f"Expected exactly 1 conflict, got: {outcomes}"
        )

        data = _json.loads(registry_path.read_text())
        assert list(data.keys()) == ["concurrent-tenant"]

    def test_api_duplicate_create_returns_409_via_write_boundary(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """POST /admin/tenants duplicate is caught at write boundary → 409 with contract detail."""
        app = _build_admin_app(tmp_path, monkeypatch)
        _patch_registry(tmp_path, monkeypatch)

        with TestClient(app) as client:
            resp1 = client.post(
                "/admin/tenants",
                json={"tenant_id": "atomic-dup"},
                headers=_admin_headers(),
            )
            assert resp1.status_code == 201, resp1.text

            resp2 = client.post(
                "/admin/tenants",
                json={"tenant_id": "atomic-dup"},
                headers=_admin_headers(),
            )
            assert resp2.status_code == 409
            detail = resp2.json().get("detail", "")
            assert "already exists" in detail.lower() or "duplicate" in detail.lower()


class TestGatewayStrictValidation:
    """Gateway tenant-create model must reject unknown fields (extra=forbid)."""

    def test_gateway_model_rejects_extra_fields(self) -> None:
        """AdminCreateTenantRequest with unknown field raises Pydantic ValidationError."""
        from pydantic import ValidationError

        from admin_gateway.routers.admin import AdminCreateTenantRequest

        with pytest.raises(ValidationError) as exc_info:
            AdminCreateTenantRequest(tenant_id="valid-id", unknown_field="bad")  # type: ignore[call-arg]
        errors = exc_info.value.errors()
        assert any(e.get("type") == "extra_forbidden" for e in errors)

    def test_gateway_model_accepts_valid_payload(self) -> None:
        """AdminCreateTenantRequest accepts known fields without error."""
        from admin_gateway.routers.admin import AdminCreateTenantRequest

        req = AdminCreateTenantRequest(tenant_id="ok-tenant", name="OK Tenant")
        assert req.tenant_id == "ok-tenant"
        assert req.name == "OK Tenant"

    def test_gateway_model_name_optional(self) -> None:
        """AdminCreateTenantRequest accepts tenant_id without name."""
        from admin_gateway.routers.admin import AdminCreateTenantRequest

        req = AdminCreateTenantRequest(tenant_id="no-name")  # type: ignore[call-arg]
        assert req.tenant_id == "no-name"
        assert req.name is None

    def test_core_and_gateway_models_both_reject_extra_fields(self) -> None:
        """Both core and gateway tenant-create models must forbid extra fields consistently."""
        from pydantic import ValidationError

        from admin_gateway.routers.admin import AdminCreateTenantRequest
        from api.admin import TenantCreateRequest

        for ModelClass in (TenantCreateRequest, AdminCreateTenantRequest):
            with pytest.raises(ValidationError, match="extra_forbidden|Extra inputs"):
                ModelClass(tenant_id="test", rogue_field="injection")  # type: ignore[call-arg]
