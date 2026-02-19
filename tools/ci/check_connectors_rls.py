from __future__ import annotations

from pathlib import Path

MIGRATION = Path("migrations/postgres/0024_connectors_control_plane.sql")
TABLES = (
    "connectors_tenant_state",
    "connectors_credentials",
    "connectors_audit_ledger",
)


def main() -> int:
    body = MIGRATION.read_text(encoding="utf-8")
    failures: list[str] = []
    for table in TABLES:
        if f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY;" not in body:
            failures.append(f"RLS_ENABLE_MISSING {table}")
        if f"{table}_tenant_isolation" not in body:
            failures.append(f"RLS_POLICY_MISSING {table}")

    if failures:
        for f in failures:
            print(f)
        raise SystemExit(1)

    print("connectors RLS check passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
