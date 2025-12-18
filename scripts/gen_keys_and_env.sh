#!/usr/bin/env bash
set -euo pipefail

ENV_FILE="${1:-.env}"

python3 - <<'PY'
import secrets
admin = "ADMIN_" + secrets.token_urlsafe(32)
agent = "AGENT_" + secrets.token_urlsafe(32)

print(f"FG_ADMIN_KEY={admin}")
print(f"FG_AGENT_KEY={agent}")
# Admin can ingest + defend + read decisions
# Agent can ingest + read decisions (NO defend)
print(
  "FG_API_KEYS="
  f"{admin}|decisions:read,defend:write,ingest:write;"
  f"{agent}|decisions:read,ingest:write"
)
PY
