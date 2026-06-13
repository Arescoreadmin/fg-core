"""CI check: every non-FA table with a tenant_id column must have RLS coverage.

FA tables are covered dynamically by migrations 0094/0095.
Agent-phase2 tables are validated by check_agent_phase2_rls.py.
Connector tables are validated by check_connectors_rls.py.

This check validates all remaining non-FA tables with tenant_id have:
  1. ALTER TABLE <table> ENABLE ROW LEVEL SECURITY; (in any migration)
  2. CREATE POLICY <table>_tenant_isolation ON <table> (in any migration)
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
MIGRATIONS_DIR = REPO / "migrations" / "postgres"

_CREATE_TABLE_RE = re.compile(
    r"CREATE TABLE\s+(?:IF NOT EXISTS\s+)?(\w+)\s*\(([^;]+?)\);",
    re.DOTALL | re.IGNORECASE,
)
_RLS_ENABLE_RE = re.compile(
    r"ALTER TABLE\s+(?:IF EXISTS\s+)?(\w+)\s+ENABLE ROW LEVEL SECURITY",
    re.IGNORECASE,
)
_RLS_POLICY_RE = re.compile(
    r"CREATE POLICY\s+(\w+)_tenant_isolation\s+ON\s+\1",
    re.IGNORECASE,
)
_RLS_DISABLE_RE = re.compile(
    r"ALTER TABLE\s+(?:IF EXISTS\s+)?(\w+)\s+DISABLE ROW LEVEL SECURITY",
    re.IGNORECASE,
)
_WRONG_GUC_RE = re.compile(
    r"app\.current_tenant_id",
    re.IGNORECASE,
)
_SQL_LINE_COMMENT_RE = re.compile(r"--[^\n]*")

# Migration files known to contain app.current_tenant_id in policy USING clauses —
# all fixed at runtime by migration 0111. Exempt from the GUC regression check.
_LEGACY_GUC_PATCHED_MIGRATIONS: frozenset[str] = frozenset(
    {
        "0093_fa_engagement_audit_events_replay_repair.sql",
        "0094_fa_rls_replay_repair.sql",
        "0095_fa_rls_all_tables_replay_repair.sql",
        "0096_fa_quarantined_scans_replay_repair.sql",
        "0097_fa_orm_substrate_replay_repair.sql",
        "0105_fa_evidence_provenance.sql",
        "0107_evidence_report_link_authority.sql",
        "0108_trust_intelligence_authority.sql",
        "0109_auditor_proof_authority.sql",
    }
)
_DROP_POLICY_RE = re.compile(
    r"DROP POLICY\s+(?:IF EXISTS\s+)?(\w+_tenant_isolation)\s+ON\s+(\w+)",
    re.IGNORECASE,
)

# Tables that use non-standard policy names (e.g., abbreviated aliases or
# append-only multi-policy patterns). Each entry is validated manually and
# confirmed to have tenant-scoped access control via alternative policy names.
_NONSTANDARD_POLICY_TABLES: frozenset[str] = frozenset(
    {
        # 0027_control_plane_v2.sql: cp_commands_tenant_isolation ON control_plane_commands
        "control_plane_commands",
        # 0027_control_plane_v2.sql: cp_event_ledger_tenant_isolation ON control_plane_event_ledger
        "control_plane_event_ledger",
        # 0027_control_plane_v2.sql: cp_heartbeats_tenant_isolation ON control_plane_heartbeats
        "control_plane_heartbeats",
        # 0081_portal_grant_audit_append_only.sql: portal_grant_audit_select +
        # portal_grant_audit_insert (append-only; tenant scope via portal_grants FK)
        "portal_grant_audit_events",
        # 0027: control_plane_command_receipts — no tenant_id col; RLS-enabled but
        # no tenant policy (receipts reference commands by id, not tenant-scoped directly)
        "control_plane_command_receipts",
    }
)

# Prefixes whose tables are covered by dedicated dynamic migrations or
# dedicated CI checks — exclude from this check to avoid double-reporting.
_DYNAMIC_PREFIXES: tuple[str, ...] = ("fa_",)

# Tables covered by check_agent_phase2_rls.py (0024/0025 migrations).
_AGENT_PHASE2_TABLES: frozenset[str] = frozenset(
    {
        "agent_device_identities",
        "agent_commands",
        "agent_policy_bundles",
        "agent_log_anchors",
        "agent_quarantine_events",
        "agent_update_rollouts",
        "agent_rate_budget_counters",
    }
)

# Tables covered by check_connectors_rls.py (0026 migration).
_CONNECTOR_TABLES: frozenset[str] = frozenset(
    {
        "connectors_tenant_state",
        "connectors_credentials",
        "connectors_audit_ledger",
        "connectors_idempotency",
    }
)


def _is_excluded(table: str) -> bool:
    if any(table.startswith(p) for p in _DYNAMIC_PREFIXES):
        return True
    return (
        table in _AGENT_PHASE2_TABLES
        or table in _CONNECTOR_TABLES
        or table in _NONSTANDARD_POLICY_TABLES
    )


def main() -> int:
    if not MIGRATIONS_DIR.exists():
        print(f"MISSING migrations directory: {MIGRATIONS_DIR}")
        return 1

    all_sql = ""
    rls_enabled: set[str] = set()
    rls_policies: set[str] = set()

    for p in sorted(MIGRATIONS_DIR.glob("*.sql")):
        sql = p.read_text(encoding="utf-8")
        all_sql += sql + "\n"

        # Per-file RLS enable/disable — process in position order so the
        # last statement in the file wins (handles DISABLE then re-ENABLE).
        enable_ops: list[tuple[int, bool, str]] = []
        for m in _RLS_ENABLE_RE.finditer(sql):
            enable_ops.append((m.start(), True, m.group(1)))
        for m in _RLS_DISABLE_RE.finditer(sql):
            enable_ops.append((m.start(), False, m.group(1)))
        for _, enabled, table in sorted(enable_ops):
            if enabled:
                rls_enabled.add(table)
            else:
                rls_enabled.discard(table)

        # Per-file policy create/drop — a DROP followed by CREATE in the same
        # file is the idempotent recreation pattern (net effect: policy exists).
        # A DROP with no subsequent CREATE in the same file is a regression.
        created_in_file: set[str] = {m.group(1) for m in _RLS_POLICY_RE.finditer(sql)}
        dropped_in_file: set[str] = {m.group(2) for m in _DROP_POLICY_RE.finditer(sql)}

        rls_policies.update(created_in_file)
        rls_policies -= dropped_in_file - created_in_file  # dropped but not recreated

    tables_with_tenant: set[str] = set()
    for m in _CREATE_TABLE_RE.finditer(all_sql):
        if "tenant_id" in m.group(2):
            tables_with_tenant.add(m.group(1))

    failures: list[str] = []

    # Scan every migration file for the wrong GUC name in policy USING clauses.
    # Strip single-line SQL comments first to avoid false positives from documentation.
    # Legacy migrations 0093-0109 are exempt: the bug is fixed at runtime by 0111.
    for p in sorted(MIGRATIONS_DIR.glob("*.sql")):
        if p.name in _LEGACY_GUC_PATCHED_MIGRATIONS:
            continue
        sql = p.read_text(encoding="utf-8")
        sql_code = _SQL_LINE_COMMENT_RE.sub("", sql)
        if _WRONG_GUC_RE.search(sql_code):
            failures.append(
                f"WRONG_GUC_NAME      {p.name}"
                " (uses app.current_tenant_id; must use app.tenant_id)"
            )
    for table in sorted(tables_with_tenant):
        if _is_excluded(table):
            continue
        if table not in rls_enabled:
            failures.append(f"RLS_ENABLE_MISSING  {table}")
        if table not in rls_policies:
            failures.append(f"RLS_POLICY_MISSING  {table}")

    if failures:
        print("core RLS check: FAILED")
        for f in failures:
            print(f"  {f}")
        return 1

    covered = sum(1 for t in tables_with_tenant if not _is_excluded(t))
    print(f"core RLS check: OK ({covered} tables verified)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
