#!/usr/bin/env bash
# setup_codex_env.sh — FrostGate Core (Codex + Full-Gate capable bootstrap)

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

PYTHON_BIN="${PYTHON_BIN:-python3}"
VENV_DIR="${VENV_DIR:-.venv}"

MODE="${MODE:-full}"                         # full | bootstrap
OFFLINE="${OFFLINE:-0}"
ALLOW_SYSTEM_INSTALL="${ALLOW_SYSTEM_INSTALL:-1}"
REQUIRE_FULL_GATES="${REQUIRE_FULL_GATES:-1}"

die(){ echo "ERROR: $*" >&2; exit 1; }
have(){ command -v "$1" >/dev/null 2>&1; }

echo "==> Root: ${ROOT}"
echo "==> Mode: ${MODE}"
echo "==> Python: ${PYTHON_BIN}"
echo "==> Venv: ${VENV_DIR}"

# ---------- Python ----------
$PYTHON_BIN -V >/dev/null 2>&1 || die "python not found"

if [ -d "${VENV_DIR}" ] && [ -x "${VENV_DIR}/bin/python" ]; then
  echo "==> Using existing venv"
else
  echo "==> Creating venv"
  $PYTHON_BIN -m venv "$VENV_DIR"
fi

. "${VENV_DIR}/bin/activate"

python -m pip install -U pip wheel setuptools

# ---------- Toolchain ----------
python -m pip install -U ruff mypy pytest pip-audit pre-commit pip-tools types-requests

# ---------- Dependencies ----------
if [ -f requirements.lock.txt ]; then
  pip install -r requirements.lock.txt
elif [ -f requirements.txt ]; then
  pip install -r requirements.txt
fi

if [ -f requirements-dev.lock.txt ]; then
  pip install -r requirements-dev.lock.txt
elif [ -f requirements-dev.txt ]; then
  pip install -r requirements-dev.txt
fi

python -m pip check

# ---------- Docker (CRITICAL) ----------
ensure_docker() {
  if have docker && docker compose version >/dev/null 2>&1; then
    echo "==> Docker already available"
    return
  fi

  if [ "${ALLOW_SYSTEM_INSTALL}" != "1" ]; then
    die "Docker required but system install not allowed"
  fi

  if have apt-get; then
    echo "==> Installing Docker"
    apt-get update
    apt-get install -y docker.io docker-compose-plugin

    if have systemctl; then
      systemctl start docker || true
    fi
  else
    die "No apt-get available to install Docker"
  fi

  have docker || die "Docker install failed"
}

if [ "${REQUIRE_FULL_GATES}" = "1" ]; then
  ensure_docker
fi

# ---------- Snapshot ----------
echo "==> Snapshot"
{
  echo "python=$(python --version)"
  echo "pip=$(python -m pip --version)"
  echo "docker=$(docker --version 2>&1 || true)"
  echo "compose=$(docker compose version 2>&1 || true)"
} > .codex_env_snapshot.txt

echo "==> Bootstrap complete"

if [ "${REQUIRE_FULL_GATES}" = "1" ]; then
  echo "Next: bash codex_gates.sh"
else
  echo "Next: python-only execution"
fi