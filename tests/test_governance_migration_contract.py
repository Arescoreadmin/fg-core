from __future__ import annotations

from pathlib import Path


def test_governance_migration_0006_is_idempotent_guarded() -> None:
    sql = Path("migrations/postgres/0006_governance_tenant_scope.sql").read_text(
        encoding="utf-8"
    )

    assert "information_schema.columns" in sql
    assert "ADD COLUMN tenant_id" in sql
    assert "ALTER COLUMN tenant_id SET NOT NULL" in sql
    assert "IF col_not_null THEN" in sql
    assert "WHERE tenant_id IS NULL" in sql
    assert (
        "CREATE INDEX IF NOT EXISTS idx_policy_change_requests_tenant_proposed_id"
        in sql
    )
    assert "CREATE INDEX IF NOT EXISTS idx_policy_change_requests_tenant_id_id" in sql


def test_contract_governance_scoped_vs_unscoped_semantics_present() -> None:
    text = Path("CONTRACT.md").read_text(encoding="utf-8")

    assert "Scoped key semantics" in text
    assert "Unscoped key semantics" in text
    assert "writes always persist `tenant_id` from `request.state.tenant_id`" in text
