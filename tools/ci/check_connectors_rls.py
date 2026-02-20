# tools/ci/check_connectors_rls.py
from __future__ import annotations

from pathlib import Path

MIGRATION = Path("migrations/postgres/0025_agent_phase21_hardening.sql")
MIGRATIONS_DIR = Path("migrations/postgres")

TABLES = (
    "connectors_tenant_state",
    "connectors_credentials",
    "connectors_audit_ledger",
    "connectors_idempotency",
)


def _require_contains(body: str, needle: str, failures: list[str], code: str) -> None:
    if needle not in body:
        failures.append(f"{code} {needle}")


def main() -> int:
    if not MIGRATIONS_DIR.exists():
        print(f"RLS_MIGRATIONS_DIR_MISSING {MIGRATIONS_DIR}")
        raise SystemExit(1)

    bodies = []
    for p in sorted(MIGRATIONS_DIR.glob("*.sql")):
        bodies.append(p.read_text(encoding="utf-8"))
    body = "\n".join(bodies)

    failures: list[str] = []
    for table in TABLES:
        _require_contains(
            body,
            f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY;",
            failures,
            "RLS_ENABLE_MISSING",
        )
        _require_contains(
            body,
            f"CREATE POLICY {table}_tenant_isolation ON {table}",
            failures,
            "RLS_POLICY_MISSING",
        )

    if failures:
        for f in failures:
            print(f)
        raise SystemExit(1)

    print("connectors RLS check passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
