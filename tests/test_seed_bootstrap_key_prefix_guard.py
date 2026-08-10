from __future__ import annotations

import pytest

from tools.seed import run_seed


def test_default_seed_keys_have_distinct_prefix_identity() -> None:
    admin_prefix = run_seed._seed_key_prefix_identity(run_seed.DEFAULT_ADMIN_KEY)
    agent_prefix = run_seed._seed_key_prefix_identity(run_seed.DEFAULT_AGENT_KEY)
    assert admin_prefix != agent_prefix


def test_guard_fails_when_seed_prefix_identities_collide() -> None:
    with pytest.raises(run_seed.SeedBootstrapError) as exc:
        run_seed._assert_distinct_key_prefixes(
            admin_key="fg_admin_seed_primary_key_000000000000",
            agent_key="fg_agent_seed_primary_key_000000000000",
        )
    assert "SEED_CONFLICT:key_prefix_collision" in str(exc.value)


def test_seed_credentials_are_canonical_and_reused(tmp_path, monkeypatch) -> None:
    from api.credential_authority import validate_credential
    from api.db import get_engine, init_db, reset_engine_cache

    db_path = tmp_path / "seed.db"
    registry_path = tmp_path / "tenants.json"
    state_path = tmp_path / "bootstrap_state.json"
    monkeypatch.setenv("FG_SQLITE_PATH", str(db_path))
    monkeypatch.setenv("FG_TENANT_REGISTRY_PATH", str(registry_path))
    reset_engine_cache()
    init_db(sqlite_path=str(db_path))

    config = run_seed.SeedConfig(
        sqlite_path=str(db_path),
        registry_path=str(registry_path),
        state_path=str(state_path),
        tenant_id="tenant-seed-primary",
    )

    payload = run_seed._ensure_seed_credentials(config, {})
    credentials = payload["seed_credentials"]
    assert set(credentials) == {"admin_api_key", "agent_api_key", "audit_api_key"}
    assert payload["ag_core_api_key"] == credentials["audit_api_key"]
    assert all(value.startswith("fgk.") for value in credentials.values())

    engine = get_engine()
    for role, spec in run_seed.SEED_CREDENTIAL_SPECS.items():
        principal = validate_credential(engine, credentials[f"{role}_api_key"])
        assert principal.tenant_id == config.tenant_id
        assert principal.credential_slot == spec["slot"]
        assert set(spec["scopes"]).issubset(principal.scopes)

    reused = run_seed._ensure_seed_credentials(config, payload.copy())
    assert reused["seed_credentials"] == credentials
    assert reused["seed_credential_status"] == {
        "admin": "existing",
        "agent": "existing",
        "audit": "existing",
    }


def test_seed_credentials_backfill_legacy_marker(tmp_path, monkeypatch) -> None:
    from api.db import init_db, reset_engine_cache

    db_path = tmp_path / "legacy-seed.db"
    registry_path = tmp_path / "tenants.json"
    state_path = tmp_path / "bootstrap_state.json"
    monkeypatch.setenv("FG_SQLITE_PATH", str(db_path))
    monkeypatch.setenv("FG_TENANT_REGISTRY_PATH", str(registry_path))
    reset_engine_cache()
    init_db(sqlite_path=str(db_path))

    config = run_seed.SeedConfig(
        sqlite_path=str(db_path),
        registry_path=str(registry_path),
        state_path=str(state_path),
        tenant_id="tenant-seed-primary",
    )
    payload = {
        "tenant_id": config.tenant_id,
        "sqlite_path": config.sqlite_path,
        "registry_path": config.registry_path,
    }

    updated = run_seed._ensure_seed_credentials(config, payload)

    assert updated["seed_credential_status"] == {
        "admin": "issued",
        "agent": "issued",
        "audit": "issued",
    }
    assert updated["ag_core_api_key"].startswith("fgk.")


def test_demo_credential_force_rotate_uses_rotation_path(tmp_path, monkeypatch) -> None:
    from api.credential_authority import validate_credential
    from api.db import ensure_tenant_canonical_row, init_db, reset_engine_cache
    from sqlalchemy import text
    from tools.seed import demo_tenants

    db_path = tmp_path / "demo-rotate.db"
    monkeypatch.setenv("FG_SQLITE_PATH", str(db_path))
    monkeypatch.setenv("FG_ENV", "test")
    reset_engine_cache()
    init_db(sqlite_path=str(db_path))
    tenant = demo_tenants.DemoTenant(
        tenant_id="demo-rotate",
        tenant_label="Demo Rotate",
        client_name="Demo Rotate",
        client_domain="demo.example",
        sector="test",
        assessment_type="soc2",
        portal_username="demo-rotate",
    )
    ensure_tenant_canonical_row(str(db_path), tenant.tenant_id)

    first_key, first_status = demo_tenants._create_demo_credential(tenant)
    rotated_key, rotated_status = demo_tenants._create_demo_credential(
        tenant, force_rotate=True
    )

    assert first_status == "created"
    assert rotated_status == "rotated"
    assert first_key is not None
    assert rotated_key is not None
    principal = validate_credential(demo_tenants.get_engine(), rotated_key)
    assert principal.credential_slot == "demo-bff-key"

    with demo_tenants.get_engine().connect() as conn:
        rows = conn.execute(
            text(
                "SELECT generation, status FROM tenant_credentials "
                "WHERE tenant_id = :tid AND credential_slot = 'demo-bff-key' "
                "ORDER BY generation"
            ),
            {"tid": tenant.tenant_id},
        ).fetchall()

    assert rows == [(1, "rotated"), (2, "active")]
