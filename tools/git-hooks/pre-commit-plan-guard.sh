#!/usr/bin/env bash
set -euo pipefail

ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
cd "$ROOT"

STATE="plans/30_day_repo_blitz.state.yaml"
PLAN="plans/30_day_repo_blitz.yaml"

if [[ ! -f "$STATE" || ! -f "$PLAN" ]]; then
  exit 0
fi

if ! python3 - <<'PY'
from pathlib import Path
import sys
try:
    import yaml
except Exception:
    sys.exit(0)

state = yaml.safe_load(Path("plans/30_day_repo_blitz.state.yaml").read_text()) or {}
blocked = state.get("blocked", False)
task = state.get("current_task_id", "")
if blocked:
    print(f"Commit blocked: current task {task} is marked blocked.")
    sys.exit(1)
PY
then
  exit 1
fi

if git diff --cached --name-only | grep -q '^plans/30_day_repo_blitz.state.yaml$'; then
  exit 0
fi

CURRENT_TASK="$(python3 - <<'PY'
from pathlib import Path
import sys
import yaml
state = yaml.safe_load(Path("plans/30_day_repo_blitz.state.yaml").read_text()) or {}
print(state.get("current_task_id",""))
PY
)"

LATEST="artifacts/plan/${CURRENT_TASK}_validate_latest.json"

if [[ -n "${CURRENT_TASK}" && -f "$LATEST" ]]; then
  if ! python3 - <<PY
import json, sys
from pathlib import Path
data = json.loads(Path("$LATEST").read_text())
ok = data.get("status") == "pass" or bool(data.get("success"))
sys.exit(0 if ok else 1)
PY
  then
    echo "Commit blocked: latest validation for task ${CURRENT_TASK} did not pass."
    exit 1
  fi
fi

echo "Plan guard: OK"
