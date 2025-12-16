#!/usr/bin/env bash
set -euo pipefail

ENV_FILE="${1:-.env}"

python3 - <<'PY'
import secrets
admin = "ADMIN_" + secrets.token_urlsafe(32)
agent = "AGENT_" + secrets.token_urlsafe(32)

print(f"FG_ADMIN_KEY={admin}")
print(f"FG_AGENT_KEY={agent}")
print(f"FG_API_KEYS={admin}|decisions:read,defend:write;{agent}|decisions:read")
PY
