#!/usr/bin/env bash
# codex_gates.sh — Enterprise gates Codex MUST run before claiming “done”
# Usage:
#   bash codex_gates.sh            # strict default
#   GATES_MODE=fast bash codex_gates.sh
#   GATES_MODE=offline bash codex_gates.sh
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

VENV_DIR="${VENV_DIR:-.venv}"
GATES_MODE="${GATES_MODE:-strict}"   # strict | fast | offline

[ -x "${VENV_DIR}/bin/python" ] || { echo "ERROR: venv missing at ${VENV_DIR}. Run setup_codex_env.sh" >&2; exit 1; }
# shellcheck disable=SC1091
. "${VENV_DIR}/bin/activate"

echo "==> Gates mode: ${GATES_MODE}"

echo "==> Gates: ruff (lint)"
ruff check .

if ruff --help | grep -q "format"; then
  echo "==> Gates: ruff (format check)"
  ruff format --check .
fi

echo "==> Gates: mypy"
# Strict by default. If you want optional, make it explicit in fast mode.
# mypy is not in requirements-dev.txt; skip with warning if not installed.
if command -v mypy >/dev/null 2>&1; then
  if [ "${GATES_MODE}" = "fast" ]; then
    mypy . || { echo "WARN: mypy failed in fast mode (non-blocking)"; }
  else
    mypy .
  fi
else
  echo "WARN: mypy not installed — skipping type checks (add mypy to requirements-dev.txt to enforce)"
fi

echo "==> Gates: pytest"
pytest -q

echo "==> Gates: pip check"
python -m pip check

echo "==> Gates: basic secret scan (cheap tripwire)"
# Detect accidental key commits. See tests/test_secret_scan_gate.py for
# regression coverage of both the detector pattern and the safe-ref filter.
#
# Detector: env-var names require '=' so that name-only references (comments,
# shell presence tests, GH Actions env blocks, markdown, process.env access)
# are eliminated at detection time rather than by a broad post-filter.
# PEM markers and Slack tokens are matched without '=' (they are never
# legitimate as bare strings in source).
#
# Post-filter: only placeholder assignment values remain after the tighter
# detector, so the filter is narrow:
#   VAR=...  VAR=<placeholder>   documentation placeholder
#   VAR=${{ secrets.X }}         GitHub Actions inline injection (unusual but valid)
#
# Excluded paths (third-party or generated content, or files that contain the
# detection strings as code/fixture data rather than actual credentials):
#   codex_gates.sh                    contains the detection pattern strings
#   tests/test_secret_scan_gate.py    contains fixture strings with the patterns
#   .claude/worktrees/**              scratch space may hold stale detector regexes
#   services/ai_plane_extension/policy_engine.py  re.compile deny-list, not secrets
#   .venv/**                          Python virtualenv — third-party code
#   apps/**/node_modules/**           third-party JS (e.g. jose) with PEM marker strings
#   apps/**/.next/**                  Next.js build artifacts that bundle those strings
#   docs/ai/**                        audit logs and PR fix log quote env-var names as docs
#   .git/**                           git internals (COMMIT_EDITMSG) quote detector patterns
_SAFE_REF='=\.\.\.(\s|$)|=<[^>]*>|\$\{\{[^}]*\}\}'
_SECRET_HITS=$(rg -n --hidden --no-ignore-vcs \
  --glob '!codex_gates.sh' \
  --glob '!tests/test_secret_scan_gate.py' \
  --glob '!.claude/worktrees/**' \
  --glob '!services/ai_plane_extension/policy_engine.py' \
  --glob '!.venv/**' \
  --glob '!apps/**/node_modules/**' \
  --glob '!apps/**/.next/**' \
  --glob '!docs/ai/**' \
  --glob '!.git/**' \
  "(OPENAI_API_KEY|AWS_SECRET_ACCESS_KEY)=|(BEGIN( RSA)? PRIVATE KEY|xox[baprs]-|-----BEGIN PRIVATE KEY-----)" \
  . 2>/dev/null | grep -vE "$_SAFE_REF" || true)
if [ -n "$_SECRET_HITS" ]; then
  printf '%s\n' "$_SECRET_HITS"
  echo "ERROR: possible secret detected (see matches above)"
  exit 1
fi

echo "==> Gates: contract/authority checks (if Makefile exists)"
if [ -f Makefile ]; then
  # Prefer your existing contract lane if present.
  if grep -qE "fg-contract|contract" Makefile; then
    make fg-contract
  fi
fi

echo "==> Gates: authority integration (wiring completeness)"
PYTHONPATH=. python tools/ci/check_authority_integration.py

echo "Running PR fix log enforcement..."
scripts/ci/enforce_pr_fix_log.sh

echo "==> Gates: dependency audit"
if [ "${GATES_MODE}" = "offline" ]; then
  echo "SKIP: pip-audit (offline mode)"
elif [ -f Makefile ] && grep -qE "^pip-audit:" Makefile; then
  make pip-audit
else
  python -m pip install -q --upgrade pip-audit
  python -m pip_audit --ignore-vuln CVE-2026-4539 --ignore-vuln PYSEC-2025-183
fi

echo "==> Gates: canonical tester flow (skips if services unavailable)"
bash tools/auth/validate_tester_flow.sh

echo "==> All gates passed."
