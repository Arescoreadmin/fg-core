"""
R7 tenant persistence tests.

Tests for:
- TenantRepository CRUD (SQLite in-memory for speed)
- Migration tool (JSON → Postgres)
- Critical invariant: tenant resolves from Postgres when JSON is missing
- Registry freeze behavior
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict

import pytest
from sqlalchemy import create_engine, text

# ---------------------------------------------------------------------------
# SQL from migration 0156 (adapted for SQLite: TIMESTAMPTZ → TEXT, JSONB → TEXT)
# ---------------------------------------------------------------------------

_CREATE_SQL = """
CREATE TABLE IF NOT EXISTS tenants (
    tenant_id           VARCHAR(128)    PRIMARY KEY,
    display_name        TEXT            NOT NULL,
    lifecycle_state     VARCHAR(32)     NOT NULL DEFAULT 'active',
    created_at          TEXT            NOT NULL DEFAULT (datetime('now')),
    updated_at          TEXT            NOT NULL DEFAULT (datetime('now')),
    created_by          TEXT,
    metadata            TEXT            NOT NULL DEFAULT '{}',
    canonical_version   INTEGER         NOT NULL DEFAULT 1,
    last_reconciled_at  TEXT,
    archived_at         TEXT,
    migration_source    VARCHAR(32),
    migration_version   VARCHAR(32)
);

CREATE TABLE IF NOT EXISTS tenant_migration_ledger (
    ledger_id           VARCHAR(64)     PRIMARY KEY,
    run_at              TEXT            NOT NULL DEFAULT (datetime('now')),
    source              VARCHAR(32)     NOT NULL,
    source_checksum     VARCHAR(64),
    tenants_found       INTEGER         NOT NULL DEFAULT 0,
    tenants_created     INTEGER         NOT NULL DEFAULT 0,
    tenants_skipped     INTEGER         NOT NULL DEFAULT 0,
    tenants_failed      INTEGER         NOT NULL DEFAULT 0,
    warnings            TEXT            NOT NULL DEFAULT '[]',
    status              VARCHAR(32)     NOT NULL DEFAULT 'running',
    completed_at        TEXT
);
"""

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def sqlite_engine():
    """In-memory SQLite engine with tenants + tenant_migration_ledger tables."""
    engine = create_engine("sqlite+pysqlite:///:memory:", future=True)
    with engine.begin() as conn:
        for stmt in _CREATE_SQL.strip().split(";"):
            stmt = stmt.strip()
            if stmt:
                conn.execute(text(stmt))
    yield engine
    engine.dispose()


@pytest.fixture
def json_registry_path(tmp_path):
    """Temp tenants.json with 2 test tenants."""
    data = {
        "tenant-alpha": {
            "name": "Alpha Corp",
            "api_key": "key-alpha",
            "status": "active",
            "created_at": "2024-01-01T00:00:00+00:00",
            "updated_at": "2024-01-01T00:00:00+00:00",
        },
        "tenant-beta": {
            "name": "Beta Ltd",
            "api_key": "key-beta",
            "status": "active",
            "created_at": "2024-02-01T00:00:00+00:00",
            "updated_at": "2024-02-01T00:00:00+00:00",
        },
    }
    p = tmp_path / "tenants.json"
    p.write_text(json.dumps(data), encoding="utf-8")
    return p


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------


def _make_repo(engine):
    from api.tenant_repository import TenantRepository

    return TenantRepository(engine)


# ---------------------------------------------------------------------------
# TenantRepository CRUD tests
# ---------------------------------------------------------------------------


def test_repository_create_and_get(sqlite_engine):
    repo = _make_repo(sqlite_engine)
    row = repo.create(
        "acme",
        "Acme Corp",
        created_by="test-actor",
        migration_source="test",
    )
    assert row.tenant_id == "acme"
    assert row.display_name == "Acme Corp"
    assert row.lifecycle_state == "active"
    assert row.created_by == "test-actor"

    fetched = repo.get("acme")
    assert fetched is not None
    assert fetched.tenant_id == "acme"
    assert fetched.display_name == "Acme Corp"


def test_repository_create_duplicate_raises(sqlite_engine):
    repo = _make_repo(sqlite_engine)
    repo.create("dup-tenant", "Dup Tenant")
    with pytest.raises(ValueError, match="already exists"):
        repo.create("dup-tenant", "Dup Tenant Again")


def test_repository_get_missing_returns_none(sqlite_engine, monkeypatch):
    # Disable JSON fallback so we're testing pure Postgres path.
    monkeypatch.setattr(
        "tools.tenants.registry.load_registry",
        lambda: {},
    )
    repo = _make_repo(sqlite_engine)
    result = repo.get("nonexistent-tenant-xyz")
    assert result is None


def test_repository_list_all(sqlite_engine):
    repo = _make_repo(sqlite_engine)
    repo.create("t1", "Tenant One")
    repo.create("t2", "Tenant Two")
    rows = repo.list_all()
    ids = [r.tenant_id for r in rows]
    assert "t1" in ids
    assert "t2" in ids
    assert len(rows) == 2


def test_repository_set_lifecycle_state(sqlite_engine):
    repo = _make_repo(sqlite_engine)
    repo.create("ls-tenant", "Lifecycle Tenant")
    updated = repo.set_lifecycle_state("ls-tenant", "suspended")
    assert updated.lifecycle_state == "suspended"

    fetched = repo._pg_get("ls-tenant")
    assert fetched is not None
    assert fetched.lifecycle_state == "suspended"


def test_repository_set_lifecycle_state_unknown_raises(sqlite_engine):
    repo = _make_repo(sqlite_engine)
    repo.create("ls-tenant2", "Lifecycle Tenant 2")
    with pytest.raises(ValueError, match="Unknown lifecycle state"):
        repo.set_lifecycle_state("ls-tenant2", "nonexistent-state")


def test_repository_set_lifecycle_state_missing_raises(sqlite_engine):
    repo = _make_repo(sqlite_engine)
    with pytest.raises(KeyError):
        repo.set_lifecycle_state("ghost-tenant", "suspended")


# ---------------------------------------------------------------------------
# Migration tool tests
# ---------------------------------------------------------------------------


def test_migration_empty_json(sqlite_engine, tmp_path, monkeypatch):
    """No JSON file → migration completes gracefully, 0 tenants created."""
    from tools.tenants import migrate_to_postgres as m

    monkeypatch.setattr(m, "REGISTRY_PATH", tmp_path / "tenants.json")
    # Override dialect check to allow SQLite for testing.
    monkeypatch.setattr(
        sqlite_engine.dialect, "name", "postgresql", raising=False
    )

    result = m.run_migration(engine=sqlite_engine, stop_json_writes=False)
    assert result.status == "complete"
    assert result.tenants_created == 0


def test_migration_creates_rows(sqlite_engine, tmp_path, monkeypatch, json_registry_path):
    """JSON with 2 tenants → 2 Postgres rows."""
    from tools.tenants import migrate_to_postgres as m

    monkeypatch.setattr(m, "REGISTRY_PATH", json_registry_path)
    monkeypatch.setattr(sqlite_engine.dialect, "name", "postgresql", raising=False)

    result = m.run_migration(engine=sqlite_engine, stop_json_writes=False)
    assert result.status == "complete"
    assert result.tenants_created == 2
    assert result.tenants_failed == 0

    repo = _make_repo(sqlite_engine)
    assert repo._pg_get("tenant-alpha") is not None
    assert repo._pg_get("tenant-beta") is not None


def test_migration_idempotent(sqlite_engine, tmp_path, monkeypatch, json_registry_path):
    """Run twice → second run: 0 created, 2 skipped."""
    from tools.tenants import migrate_to_postgres as m

    monkeypatch.setattr(m, "REGISTRY_PATH", json_registry_path)
    monkeypatch.setattr(sqlite_engine.dialect, "name", "postgresql", raising=False)

    result1 = m.run_migration(engine=sqlite_engine, stop_json_writes=False)
    assert result1.tenants_created == 2

    result2 = m.run_migration(engine=sqlite_engine, stop_json_writes=False)
    assert result2.tenants_created == 0
    assert result2.tenants_skipped == 2
    assert result2.status == "complete"


def test_migration_malformed_record(sqlite_engine, tmp_path, monkeypatch):
    """One valid tenant, one with empty name → warning, 1 created, 1 failed."""
    from tools.tenants import migrate_to_postgres as m

    data = {
        "good-tenant": {
            "name": "Good Tenant",
            "status": "active",
        },
        "bad-tenant": {
            "name": "",  # empty name — malformed
            "status": "active",
        },
    }
    p = tmp_path / "tenants.json"
    p.write_text(json.dumps(data))

    monkeypatch.setattr(m, "REGISTRY_PATH", p)
    monkeypatch.setattr(sqlite_engine.dialect, "name", "postgresql", raising=False)

    result = m.run_migration(engine=sqlite_engine, stop_json_writes=False)
    assert result.tenants_created == 1
    assert result.tenants_failed == 1
    assert len(result.warnings) >= 1
    assert result.status == "partial"


def test_migration_dry_run(sqlite_engine, tmp_path, monkeypatch, json_registry_path):
    """dry_run=True → no rows in Postgres."""
    from tools.tenants import migrate_to_postgres as m

    monkeypatch.setattr(m, "REGISTRY_PATH", json_registry_path)
    monkeypatch.setattr(sqlite_engine.dialect, "name", "postgresql", raising=False)

    result = m.run_migration(engine=sqlite_engine, dry_run=True, stop_json_writes=False)
    assert result.status == "dry_run"

    repo = _make_repo(sqlite_engine)
    assert repo._pg_get("tenant-alpha") is None
    assert repo._pg_get("tenant-beta") is None


# ---------------------------------------------------------------------------
# JSON fallback / priority tests
# ---------------------------------------------------------------------------


def _mock_registry(records: Dict[str, Any]):
    """Return a mock load_registry callable."""
    from tools.tenants.registry import TenantRecord

    def _loader():
        return {
            tid: TenantRecord(
                tenant_id=tid,
                name=v["name"],
                api_key=v.get("api_key", "k"),
                status=v.get("status", "active"),
                created_at=v.get("created_at", "2024-01-01T00:00:00+00:00"),
                updated_at=v.get("updated_at", "2024-01-01T00:00:00+00:00"),
            )
            for tid, v in records.items()
        }

    return _loader


def test_json_fallback_when_not_in_postgres(sqlite_engine, monkeypatch):
    """Tenant not in Postgres but in JSON → repo.get() returns the JSON record."""
    import tools.tenants.registry as reg_mod

    monkeypatch.setattr(
        reg_mod,
        "load_registry",
        _mock_registry(
            {
                "json-only-tenant": {
                    "name": "JSON Only",
                    "status": "active",
                }
            }
        ),
    )

    repo = _make_repo(sqlite_engine)
    row = repo.get("json-only-tenant")
    assert row is not None
    assert row.tenant_id == "json-only-tenant"
    assert row.display_name == "JSON Only"
    assert row.migration_source == "json"


def test_postgres_takes_priority_over_json(sqlite_engine, monkeypatch):
    """Tenant in BOTH Postgres (display_name='postgres') and JSON (name='json') → Postgres wins."""
    import tools.tenants.registry as reg_mod

    monkeypatch.setattr(
        reg_mod,
        "load_registry",
        _mock_registry(
            {
                "shared-tenant": {
                    "name": "json",
                    "status": "active",
                }
            }
        ),
    )

    repo = _make_repo(sqlite_engine)
    # Insert Postgres record first.
    repo.create("shared-tenant", "postgres")

    row = repo.get("shared-tenant")
    assert row is not None
    assert row.display_name == "postgres"


# ---------------------------------------------------------------------------
# Critical invariant
# ---------------------------------------------------------------------------


def test_critical_invariant_resolves_without_json(sqlite_engine, monkeypatch):
    """
    THE KEY TEST: tenant must resolve from Postgres even when JSON is missing.

    Steps:
    1. Create tenant via repo.create()
    2. Verify _pg_get() returns it
    3. Monkeypatch load_registry to raise FileNotFoundError
    4. repo.get() must STILL return the tenant (from Postgres)
    """
    import tools.tenants.registry as reg_mod

    repo = _make_repo(sqlite_engine)
    repo.create("critical-tenant", "Critical Tenant")

    # Verify it's in Postgres.
    pg_row = repo._pg_get("critical-tenant")
    assert pg_row is not None, "Tenant must be in Postgres after create()"

    # Hide the JSON file.
    def _raise_fnf():
        raise FileNotFoundError("JSON hidden")

    monkeypatch.setattr(reg_mod, "load_registry", _raise_fnf)

    # Must still resolve from Postgres.
    row = repo.get("critical-tenant")
    assert row is not None, (
        "CRITICAL INVARIANT VIOLATED: tenant must resolve from Postgres "
        "even when state/tenants.json is hidden"
    )
    assert row.tenant_id == "critical-tenant"
    assert row.display_name == "Critical Tenant"


# ---------------------------------------------------------------------------
# Registry freeze test
# ---------------------------------------------------------------------------


def test_freeze_blocks_exclusive_create(tmp_path, monkeypatch):
    """After .frozen sentinel is created, create_tenant_exclusive() must raise TenantRegistryFrozenError."""
    import tools.tenants.registry as reg_mod
    from tools.tenants.registry import TenantRegistryFrozenError

    # Point registry to tmp_path.
    registry_path = tmp_path / "tenants.json"
    registry_path.write_text("{}", encoding="utf-8")
    monkeypatch.setattr(reg_mod, "REGISTRY_PATH", registry_path)

    # Create the .frozen sentinel.
    frozen_path = registry_path.with_suffix(".frozen")
    frozen_path.write_text(
        json.dumps({"frozen_at": "2024-01-01T00:00:00+00:00", "migration_version": "r7-v1"}),
        encoding="utf-8",
    )

    with pytest.raises(TenantRegistryFrozenError):
        reg_mod.create_tenant_exclusive("new-tenant", "New Tenant")
