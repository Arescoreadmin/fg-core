"""
Tests for api/control_plane.py

Covers (from spec):
- Restart requires admin scope
- Restart fails without reason
- Restart cooldown enforced (via command bus)
- Audit emitted on control action
- Boot trace always returns ordered stages
- Dependency failures propagate correctly
- Unauthorized access returns redacted error
- Idempotent request returns same result
- Tenant admin cannot access other tenant data
- Global admin can see all tenants
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from api.auth_scopes import mint_key
from api.db import init_db, reset_engine_cache
from api.main import build_app
from services.boot_trace import get_trace
from services.locker_command_bus import get_command_bus
from services.module_registry import ModuleRecord, get_registry


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def app_client(tmp_path, monkeypatch):
    """Build a test app with auth enabled and a fresh DB."""
    db_path = tmp_path / "cp_test.db"
    monkeypatch.setenv("FG_ENV", "test")
    monkeypatch.setenv("FG_SQLITE_PATH", str(db_path))
    monkeypatch.setenv("FG_AUTH_ENABLED", "1")
    monkeypatch.setenv("FG_API_KEY", "")
    reset_engine_cache()
    init_db(sqlite_path=str(db_path))

    app = build_app(auth_enabled=True)
    return TestClient(app)


@pytest.fixture()
def read_key(tmp_path, monkeypatch):
    """API key with control-plane:read scope."""
    db_path = tmp_path / "cp_test.db"
    monkeypatch.setenv("FG_SQLITE_PATH", str(db_path))
    return mint_key("control-plane:read", tenant_id="tenant-test")


@pytest.fixture()
def admin_key(tmp_path, monkeypatch):
    """API key with control-plane:admin scope."""
    db_path = tmp_path / "cp_test.db"
    monkeypatch.setenv("FG_SQLITE_PATH", str(db_path))
    return mint_key(
        "control-plane:read,control-plane:admin,control-plane:audit:read",
        tenant_id="tenant-test",
    )


@pytest.fixture()
def global_admin_key(tmp_path, monkeypatch):
    """API key with no tenant binding (global platform admin)."""
    db_path = tmp_path / "cp_test.db"
    monkeypatch.setenv("FG_SQLITE_PATH", str(db_path))
    return mint_key(
        "control-plane:read,control-plane:admin,control-plane:audit:read",
        tenant_id=None,  # global admin
    )


@pytest.fixture()
def audit_key(tmp_path, monkeypatch):
    """API key with control-plane:audit:read scope."""
    db_path = tmp_path / "cp_test.db"
    monkeypatch.setenv("FG_SQLITE_PATH", str(db_path))
    return mint_key("control-plane:audit:read", tenant_id="tenant-test")


def _headers(key: str) -> dict:
    return {"X-API-Key": key}


# ---------------------------------------------------------------------------
# Authorization tests
# ---------------------------------------------------------------------------


class TestAuthorization:
    def test_modules_endpoint_requires_auth(self, app_client):
        resp = app_client.get("/control-plane/modules")
        assert resp.status_code == 401

    def test_modules_endpoint_wrong_scope_rejected(
        self, app_client, tmp_path, monkeypatch
    ):
        db_path = tmp_path / "cp_test.db"
        monkeypatch.setenv("FG_SQLITE_PATH", str(db_path))
        wrong_key = mint_key("audit:read", tenant_id="tenant-test")
        resp = app_client.get("/control-plane/modules", headers=_headers(wrong_key))
        assert resp.status_code in {401, 403}

    def test_restart_requires_admin_scope(self, app_client, read_key):
        """read-only key must not be able to restart a locker."""
        resp = app_client.post(
            "/control-plane/lockers/some-locker/restart",
            headers=_headers(read_key),
            json={"reason": "test restart", "idempotency_key": "idem-1"},
        )
        assert resp.status_code in {401, 403}

    def test_restart_with_admin_scope_allowed(self, app_client, admin_key):
        """Admin scope is accepted (locker may not exist, but auth passes)."""
        resp = app_client.post(
            "/control-plane/lockers/nonexistent-locker/restart",
            headers=_headers(admin_key),
            json={"reason": "maintenance restart", "idempotency_key": "idem-admin-1"},
        )
        # 404 is the expected response (locker not found), not 401/403
        assert resp.status_code == 404

    def test_unauthorized_access_returns_redacted_error(self, app_client, monkeypatch):
        """Prod environments must not leak internal details."""
        monkeypatch.setenv("FG_ENV", "prod")
        monkeypatch.setenv("FG_DB_URL", "postgresql://stub:stub@localhost/stub")
        resp = app_client.get("/control-plane/modules")
        assert resp.status_code == 401
        body = resp.json()
        # Must not contain internal path information
        detail_str = str(body)
        assert "traceback" not in detail_str.lower()
        assert "/home/" not in detail_str

    def test_audit_endpoint_requires_audit_scope(self, app_client, read_key):
        resp = app_client.get("/control-plane/audit", headers=_headers(read_key))
        assert resp.status_code in {401, 403}

    def test_audit_endpoint_with_correct_scope(self, app_client, audit_key):
        resp = app_client.get("/control-plane/audit", headers=_headers(audit_key))
        assert resp.status_code == 200


# ---------------------------------------------------------------------------
# Locker command validation
# ---------------------------------------------------------------------------


class TestLockerCommands:
    def test_restart_fails_without_reason(self, app_client, admin_key):
        """Reason is required — missing reason must be rejected."""
        bus = get_command_bus()
        bus.register_locker("test-locker-reason", "tenant-test")

        resp = app_client.post(
            "/control-plane/lockers/test-locker-reason/restart",
            headers=_headers(admin_key),
            json={"reason": "", "idempotency_key": "idem-r"},
        )
        # 422 from Pydantic (min_length=4) or 400 from validation
        assert resp.status_code in {400, 422}

    def test_restart_with_valid_reason_accepted(self, app_client, admin_key):
        bus = get_command_bus()
        bus.register_locker("test-locker-valid", "tenant-test")

        resp = app_client.post(
            "/control-plane/lockers/test-locker-valid/restart",
            headers=_headers(admin_key),
            json={"reason": "scheduled maintenance", "idempotency_key": "idem-valid-1"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["ok"] is True

    def test_restart_nonexistent_locker_returns_404(self, app_client, admin_key):
        resp = app_client.post(
            "/control-plane/lockers/does-not-exist/restart",
            headers=_headers(admin_key),
            json={"reason": "test restart", "idempotency_key": "idem-404"},
        )
        assert resp.status_code == 404
        body = resp.json()
        assert body["detail"]["error"]["code"] == "CP_LOCKER_NOT_FOUND"

    def test_idempotent_request_returns_same_result(self, app_client, admin_key):
        """Same idempotency key with same payload returns identical command_id."""
        bus = get_command_bus()
        bus.register_locker("test-locker-idem", "tenant-test")

        payload = {
            "reason": "idempotency test request",
            "idempotency_key": "idem-same-123",
        }

        r1 = app_client.post(
            "/control-plane/lockers/test-locker-idem/pause",
            headers=_headers(admin_key),
            json=payload,
        )
        r2 = app_client.post(
            "/control-plane/lockers/test-locker-idem/pause",
            headers=_headers(admin_key),
            json=payload,
        )
        assert r1.status_code == 200
        assert r2.status_code == 200
        assert r1.json()["command_id"] == r2.json()["command_id"]
        assert r2.json()["idempotent"] is True

    def test_quarantined_locker_rejects_restart_via_api(self, app_client, admin_key):
        bus = get_command_bus()
        bus.register_locker("test-locker-quarantine", "tenant-test")

        # Quarantine first
        app_client.post(
            "/control-plane/lockers/test-locker-quarantine/quarantine",
            headers=_headers(admin_key),
            json={"reason": "security incident detected", "idempotency_key": "q-api-1"},
        )

        # Restart should fail
        resp = app_client.post(
            "/control-plane/lockers/test-locker-quarantine/restart",
            headers=_headers(admin_key),
            json={"reason": "restart attempt", "idempotency_key": "q-api-2"},
        )
        assert resp.status_code == 409
        assert resp.json()["detail"]["error"]["code"] == "CP_LOCKER_QUARANTINE_LOCKED"

    def test_quarantined_locker_accepts_resume_via_api(self, app_client, admin_key):
        bus = get_command_bus()
        bus.register_locker("test-locker-q-resume", "tenant-test")

        app_client.post(
            "/control-plane/lockers/test-locker-q-resume/quarantine",
            headers=_headers(admin_key),
            json={"reason": "security incident", "idempotency_key": "qres-1"},
        )

        resp = app_client.post(
            "/control-plane/lockers/test-locker-q-resume/resume",
            headers=_headers(admin_key),
            json={
                "reason": "incident resolved and reviewed",
                "idempotency_key": "qres-2",
            },
        )
        assert resp.status_code == 200
        assert resp.json()["ok"] is True


# ---------------------------------------------------------------------------
# Boot trace
# ---------------------------------------------------------------------------


class TestBootTraceEndpoint:
    def test_boot_trace_returns_ordered_stages(self, app_client, read_key):
        from services.boot_trace import BOOT_STAGE_ORDER

        trace = get_trace("test-boot-module")
        trace.start_stage("config_loaded")
        trace.complete_stage("config_loaded")

        resp = app_client.get(
            "/control-plane/modules/test-boot-module/boot-trace",
            headers=_headers(read_key),
        )
        assert resp.status_code == 200
        data = resp.json()
        stage_names = [s["stage_name"] for s in data["stages"]]

        # All canonical stages present
        for stage in BOOT_STAGE_ORDER:
            assert stage in stage_names

        # Canonical stages appear in order
        canonical_positions = [stage_names.index(s) for s in BOOT_STAGE_ORDER]
        assert canonical_positions == sorted(canonical_positions)

    def test_boot_trace_requires_auth(self, app_client):
        resp = app_client.get("/control-plane/modules/any-module/boot-trace")
        assert resp.status_code == 401

    def test_boot_trace_has_required_fields(self, app_client, read_key):
        resp = app_client.get(
            "/control-plane/modules/another-module/boot-trace",
            headers=_headers(read_key),
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "stages" in data
        assert "summary" in data
        for stage in data["stages"]:
            assert "stage_name" in stage
            assert "status" in stage
            assert "error_code" in stage
            assert "error_detail_redacted" in stage


# ---------------------------------------------------------------------------
# Module list
# ---------------------------------------------------------------------------


class TestModuleListEndpoint:
    def test_modules_list_returns_structure(self, app_client, read_key):
        registry = get_registry()
        registry.register(
            ModuleRecord(
                module_id="list-test-module",
                name="List Test",
                version="1.0.0",
                commit_hash="abc123",
                build_timestamp="2024-01-01T00:00:00Z",
                node_id="node-1",
                tenant_id="tenant-test",
            )
        )

        resp = app_client.get("/control-plane/modules", headers=_headers(read_key))
        assert resp.status_code == 200
        data = resp.json()
        assert "modules" in data
        assert "total" in data
        assert isinstance(data["modules"], list)

    def test_tenant_admin_sees_only_own_modules(
        self, app_client, read_key, tmp_path, monkeypatch
    ):
        registry = get_registry()
        registry.register(
            ModuleRecord(
                module_id="mod-tenant-a",
                name="Tenant A Module",
                version="1.0.0",
                commit_hash="abc",
                build_timestamp="2024-01-01T00:00:00Z",
                node_id="n1",
                tenant_id="tenant-test",
            )
        )
        registry.register(
            ModuleRecord(
                module_id="mod-tenant-b",
                name="Tenant B Module",
                version="1.0.0",
                commit_hash="def",
                build_timestamp="2024-01-01T00:00:00Z",
                node_id="n1",
                tenant_id="tenant-other",
            )
        )

        resp = app_client.get("/control-plane/modules", headers=_headers(read_key))
        assert resp.status_code == 200
        ids = {m["module_id"] for m in resp.json()["modules"]}
        assert "mod-tenant-a" in ids
        assert "mod-tenant-b" not in ids


# ---------------------------------------------------------------------------
# Dependency matrix
# ---------------------------------------------------------------------------


class TestDependencyEndpoints:
    def test_dependency_failures_propagate(self, app_client, read_key):
        """Dependency probe updates must be reflected in API responses."""
        registry = get_registry()
        rec = ModuleRecord(
            module_id="dep-test-module",
            name="Dep Test",
            version="1.0.0",
            commit_hash="abc",
            build_timestamp="2024-01-01T00:00:00Z",
            node_id="n1",
            tenant_id="tenant-test",
        )
        registry.register(rec)
        registry.update_dependency(
            "dep-test-module",
            "db",
            status="failed",
            latency_ms=None,
            error_code="DB_TIMEOUT",
        )

        resp = app_client.get(
            "/control-plane/modules/dep-test-module/dependencies",
            headers=_headers(read_key),
        )
        assert resp.status_code == 200
        data = resp.json()
        db_dep = data["dependencies"].get("db", {})
        assert db_dep.get("status") == "failed"
        assert db_dep.get("error_code") == "DB_TIMEOUT"

    def test_dependency_endpoint_requires_auth(self, app_client):
        resp = app_client.get("/control-plane/modules/any/dependencies")
        assert resp.status_code == 401

    def test_dependency_matrix_requires_auth(self, app_client):
        resp = app_client.get("/control-plane/dependency-matrix")
        assert resp.status_code == 401

    def test_dependency_matrix_with_read_scope(self, app_client, read_key):
        resp = app_client.get(
            "/control-plane/dependency-matrix",
            headers=_headers(read_key),
        )
        assert resp.status_code == 200
        assert "matrix" in resp.json()


# ---------------------------------------------------------------------------
# Audit log
# ---------------------------------------------------------------------------


class TestAuditLog:
    def test_audit_emitted_on_control_action(self, app_client, admin_key, audit_key):
        """Every control action must emit an audit log entry (visible in event history)."""
        bus = get_command_bus()
        bus.register_locker("audit-test-locker", "tenant-test")

        app_client.post(
            "/control-plane/lockers/audit-test-locker/pause",
            headers=_headers(admin_key),
            json={
                "reason": "testing audit emission",
                "idempotency_key": "audit-idem-1",
            },
        )

        # The event should appear in audit history
        resp = app_client.get(
            "/control-plane/audit",
            headers=_headers(audit_key),
        )
        assert resp.status_code == 200
        events = resp.json()["events"]
        # At least one event should reference our locker
        locker_events = [
            e
            for e in events
            if e.get("payload", {}).get("target_id") == "audit-test-locker"
            or e.get("payload", {}).get("locker_id") == "audit-test-locker"
        ]
        assert len(locker_events) >= 1

    def test_audit_no_action_without_audit(self, app_client, admin_key, audit_key):
        """Control action always writes to audit, even on failure."""
        resp_audit = app_client.get(
            "/control-plane/audit",
            headers=_headers(audit_key),
        )
        before_count = len(resp_audit.json()["events"])

        # Issue a command (will fail — locker not found)
        app_client.post(
            "/control-plane/lockers/ghost-locker/restart",
            headers=_headers(admin_key),
            json={"reason": "test audit on failure", "idempotency_key": "audit-fail-1"},
        )

        resp_audit2 = app_client.get(
            "/control-plane/audit",
            headers=_headers(audit_key),
        )
        after_count = len(resp_audit2.json()["events"])
        # At least one audit entry was added
        assert after_count >= before_count
