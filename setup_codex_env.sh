#!/usr/bin/env bash
# setup_codex_env.sh — FrostGate Core (Enterprise-grade local + CI-friendly bootstrap)
# Usage: bash setup_codex_env.sh
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

PYTHON_BIN="${PYTHON_BIN:-python3}"
VENV_DIR="${VENV_DIR:-.venv}"

# ---------- helpers ----------
die(){ echo "ERROR: $*" >&2; exit 1; }
have(){ command -v "$1" >/dev/null 2>&1; }

echo "==> Bootstrapping venv: ${VENV_DIR}"
$PYTHON_BIN -V >/dev/null 2>&1 || die "python not found (set PYTHON_BIN=python3.X)"

$PYTHON_BIN -m venv "$VENV_DIR"
# shellcheck disable=SC1091
. "${VENV_DIR}/bin/activate"

echo "==> Upgrading packaging toolchain"
python -m pip install -U pip wheel setuptools

echo "==> Installing quality toolchain (always)"
python -m pip install -U \
  ruff mypy pytest pip-audit pre-commit pip-tools types-requests

# ---------- dependency install (lock preferred) ----------
install_reqs() {
  local lock="$1" txt="$2"
  if [ -f "$lock" ]; then
    echo "==> Installing locked deps: $lock"
    pip install -r "$lock"
  elif [ -f "$txt" ]; then
    echo "==> Installing deps: $txt"
    pip install -r "$txt"
  else
    echo "==> Skipping missing: $lock / $txt"
  fi
}

install_reqs "requirements.lock.txt" "requirements.txt"
install_reqs "requirements-dev.lock.txt" "requirements-dev.txt"

echo "==> Verifying dependency graph (pip check)"
python -m pip check

# ---------- git hooks ----------
if [ -f .pre-commit-config.yaml ]; then
  echo "==> Installing pre-commit hooks"
  pre-commit install
else
  echo "==> No .pre-commit-config.yaml found (hooks skipped)"
fi

# ---------- optional tooling (CLI only) ----------
if have apt-get; then
  echo "==> Installing Docker CLI + compose plugin (best-effort)"
  sudo apt-get update
  sudo apt-get install -y docker.io docker-compose-plugin || true
else
  echo "==> apt-get not found (skipping docker install)"
fi

if ! have helm; then
  echo "==> Installing Helm (best-effort)"
  curl -fsSL https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash
fi

# ---------- forensics ----------
echo "==> Versions (forensics)"
python --version
python -m pip --version
ruff --version || true
mypy --version || true
pytest --version || true
pip-audit --version || true
docker version || true
docker compose version || true
helm version --short || true

# ---------- optional initial gates (non-blocking here; CI should block) ----------
echo "==> Initial quick gates (non-blocking)"
if [ -f pyproject.toml ] || [ -f ruff.toml ]; then
  ruff check . || true
fi
if [ -d tests ] || ls -1 test* >/dev/null 2>&1; then
  pytest -q || true
fi
pip-audit || true

echo "==> Done."