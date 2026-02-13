#!/usr/bin/env bash
set -euo pipefail

MAKEFILE="${1:-Makefile}"

if [[ ! -f "$MAKEFILE" ]]; then
  echo "❌ Makefile not found at: $MAKEFILE" >&2
  exit 1
fi

ts="$(date -u +%Y%m%dT%H%M%SZ)"
bak="${MAKEFILE}.bak.${ts}"
cp -a "$MAKEFILE" "$bak"
echo "✅ Backup: $bak"

# 1) Flip PY_CONTRACT to venv-only
# Handles:
#   PY_CONTRACT := $(if $(wildcard $(PY)),$(PY),python)
# or any prior definition lines that match PY_CONTRACT :=
if grep -qE '^PY_CONTRACT[[:space:]]*:?=' "$MAKEFILE"; then
  # Prefer exact replacement for your current line
  if grep -qE '^PY_CONTRACT[[:space:]]*:?=[[:space:]]*\$\(if[[:space:]]+\$\(wildcard[[:space:]]+\$\(PY\)\),\$\(PY\),python\)' "$MAKEFILE"; then
    perl -0777 -i -pe 's/^PY_CONTRACT\s*:?=\s*\$\(\s*if\s*\$\(\s*wildcard\s*\$\(\s*PY\s*\)\s*\)\s*,\s*\$\(\s*PY\s*\)\s*,\s*python\s*\)\s*$/PY_CONTRACT := $(PY)/m' "$MAKEFILE"
  else
    # Fallback: replace the whole assignment line with nuclear setting
    perl -0777 -i -pe 's/^PY_CONTRACT\s*:?=\s*.*$/PY_CONTRACT := $(PY)/m' "$MAKEFILE"
  fi
else
  # If missing entirely, insert after PY definition
  perl -0777 -i -pe 's/^(PY\s*:=.*\n)/$1PY_CONTRACT := $(PY)\n/m' "$MAKEFILE"
fi
echo "✅ Set PY_CONTRACT := \$(PY) (nuclear venv-only)"

# 2) Ensure _require-venv exists (in case you want strictness elsewhere)
if ! grep -qE '^\s*\.PHONY:\s*_require-venv\b' "$MAKEFILE"; then
  # Insert helper after Ruff section if possible, otherwise after PYTEST_ENV.
  perl -0777 -i -pe '
    if ($_ !~ /^\s*\.PHONY:\s*_require-venv\b/m) {
      my $block = qq{

# =============================================================================
# Internal helpers (nuclear: venv required)
# =============================================================================
.PHONY: _require-venv
_require-venv:
\t@test -x "$(PY)" || (echo "❌ venv missing at $(PY). Run: make venv"; exit 1)

};
      if ($_ =~ /^(RUFF\s*\?=.*\n)/m) {
        s/^(RUFF\s*\?=.*\n)/$1$block/m;
      } elsif ($_ =~ /^(PYTEST_ENV\s*:=.*\n)/m) {
        s/^(PYTEST_ENV\s*:=.*\n)/$1$block/m;
      } else {
        $_ .= $block;
      }
    }
  ' "$MAKEFILE"
  echo "✅ Added _require-venv helper"
else
  echo "↪ _require-venv already present (skipped)"
fi

# 3) Add : venv to targets that run python via PY_CONTRACT but didn't ensure venv.
# We only touch the exact targets listed here to avoid unintended edits.
targets=(
  guard-scripts
  contracts-gen
  contracts-gen-prod
  contracts-core-gen
  contracts-core-diff
  artifact-contract-check
  contract-authority-check
  verify-spine-modules
  verify-schemas
  verify-drift
  align-score
  prod-profile-check
  gap-audit
  release-gate
  generate-scorecard
  fg-contract
  fg-contract-prod
  bp-s0-001-gate
  bp-s0-005-gate
  bp-c-001-gate
  bp-c-002-gate
  bp-c-003-gate
  bp-c-004-gate
  bp-c-005-gate
  bp-c-006-gate
  bp-m1-006-gate
  bp-m2-001-gate
  bp-m2-002-gate
  bp-m2-003-gate
  bp-m3-001-gate
  bp-m3-003-gate
  bp-m3-004-gate
  bp-m3-005-gate
  bp-m3-006-gate
  bp-m3-007-gate
  bp-d-000-gate
)

for t in "${targets[@]}"; do
  # If target line exists and doesn't already list venv/_require-venv as a prerequisite, add venv.
  if grep -qE "^${t}:" "$MAKEFILE"; then
    if grep -qE "^${t}:[^\n#]*\b(venv|_require-venv)\b" "$MAKEFILE"; then
      continue
    fi
    # Add venv after the colon, preserving any existing prereqs.
    perl -0777 -i -pe "s/^(${t}:)([^\n]*)\$/\$1 venv\$2/m" "$MAKEFILE"
    echo "✅ ${t}: now depends on venv"
  fi
done

# 4) Quick sanity output
echo
echo "=== Patch complete ==="
echo "Diff summary (top 40 lines around PY_CONTRACT):"
awk '
  BEGIN{show=0;count=0}
  /^PY_CONTRACT/{show=1}
  show{print;count++}
  count>=5{exit}
' "$MAKEFILE" || true

echo
echo "Next:"
echo "  make venv"
echo "  make pr-check"
