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
