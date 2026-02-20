#!/usr/bin/env bash
set -euo pipefail

ROOT="$(pwd)"
OUT="${1:-/tmp/fg_connectors_idempotency_test_context}"
mkdir -p "$OUT"

echo "Collecting context into: $OUT"

# Core files we need to align with production patterns
FILES=(
  "services/connectors/idempotency.py"
  "api/db_models.py"
  "api/db.py"
  "api/deps.py"
  "api/connectors_control_plane.py"
  "migrations/postgres/0024_connectors_control_plane.sql"
  "migrations/postgres/0025_agent_phase21_hardening.sql"
  "tests/conftest.py"
)

for f in "${FILES[@]}"; do
  if [[ -f "$f" ]]; then
    mkdir -p "$OUT/$(dirname "$f")"
    cp -a "$f" "$OUT/$f"
  else
    echo "WARN missing: $f" | tee -a "$OUT/WARNINGS.txt"
  fi
done

# Greps to find existing patterns/fixtures/helpers
{
  echo "== Engine/session helpers =="
  rg -n "def get_engine|create_engine|Session\\(|sessionmaker|tenant_db_required|db_required|sqlite" api services tests || true
  echo
  echo "== Idempotency usage =="
  rg -n "ConnectorIdempotency|reserve_idempotency_key|connectors_idempotency" api services tests || true
  echo
  echo "== Existing connector tests =="
  rg -n "connectors_control_plane|CONNECTOR_|dispatch_ingest|ConnectorTenantState" tests || true
  echo
  echo "== RLS / migration refs =="
  rg -n "connectors_idempotency|ENABLE ROW LEVEL SECURITY|CREATE POLICY" migrations tools/ci || true
} > "$OUT/greps.txt"

# Capture python + sqlite versions for concurrency weirdness context
{
  echo "python: $(python --version 2>&1 || true)"
  echo "sqlite: $(python - <<'PY'
import sqlite3
print(sqlite3.sqlite_version)
PY
)"
} > "$OUT/versions.txt"

echo "Done. Tar it if you want:"
echo "  tar -czf ${OUT}.tar.gz -C $(dirname "$OUT") $(basename "$OUT")"