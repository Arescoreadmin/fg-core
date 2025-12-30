#!/usr/bin/env bash
set -euo pipefail

OUT="CONTEXT_SNAPSHOT.md"
ROOT="$(pwd)"

echo "Generating FrostGate Core context snapshot..."

{
echo "# FrostGate Core – Context Snapshot"
echo
echo "Generated: $(date -u +"%Y-%m-%dT%H:%M:%SZ")"
echo
echo "## Mission Lock"
echo "- Product: FrostGate Core"
echo "- Phase: MVP → Demo-Ready"
echo "- Goal: Undeniable security telemetry with explainable decisions"
echo "- Buyer Signal: stats endpoint tells a story in 10 seconds"
echo
echo "## Active Instance"
echo "- Expected API: http://127.0.0.1:8000"
echo "- DB Backend: SQLite (local dev)"
echo "- DB Path: \$FG_STATE_DIR/frostgate.db"
echo
echo "## Environment"
env | grep -E 'FG_|DATABASE|POSTGRES' || echo "(no FG env vars exported)"
echo
echo "## Running Listeners"
ss -ltnp | grep -E ':8000|:8080|:18080' || true
echo
echo "## Directory Tree (3 levels)"
find . -maxdepth 3 -type d | sed 's|^\./||'
echo
echo "## Key Files"
ls -la api scripts tests docker-compose.yml 2>/dev/null || true
echo
echo "## Decision Schema (SQLite)"
if [ -n "${FG_STATE_DIR:-}" ] && [ -f "$FG_STATE_DIR/frostgate.db" ]; then
  sqlite3 "$FG_STATE_DIR/frostgate.db" ".schema decisions"
else
  echo "⚠️ SQLite DB not found at FG_STATE_DIR"
fi
echo
echo "## Stats Snapshot"
curl -fsS http://127.0.0.1:8000/stats -H "X-API-Key: supersecret" || echo "(stats unavailable)"
echo
echo "## Known Truths"
echo "- rules_triggered_json is authoritative"
echo "- response_json is persisted correctly"
echo "- top_rules requires non-empty rules_triggered_json"
echo "- dockerized core uses Postgres and a different DB"
echo
echo "## Immediate Next Steps"
echo "- Add rule diversity (more than default_allow)"
echo "- Add time-bucket trend deltas (24h vs 7d)"
echo "- Lock demo narrative"
echo "- Optional: /stats/debug endpoint"
} > "$OUT"

echo "✅ Context snapshot written to $OUT"
