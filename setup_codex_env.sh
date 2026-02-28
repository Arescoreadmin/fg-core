#!/usr/bin/env bash
# setup_codex_env.sh — FrostGate Core (Weaponized, CI-safe, supply-chain sane bootstrap)
#
# Default posture: SAFE
# - creates/uses venv
# - installs python toolchain (+ optional pinned versions)
# - installs repo deps (prefers lockfiles)
# - runs basic verification
#
# Optional devbox posture:
#   MODE=devbox bash setup_codex_env.sh
# Optional remote installer allowance (NOT default):
#   ALLOW_REMOTE_INSTALL=1 MODE=devbox bash setup_codex_env.sh
#
# Offline mode:
#   OFFLINE=1 bash setup_codex_env.sh
#
# Usage examples:
#   bash setup_codex_env.sh
#   PYTHON_BIN=python3.12 VENV_DIR=.venv bash setup_codex_env.sh
#   MODE=devbox bash setup_codex_env.sh
#   OFFLINE=1 bash setup_codex_env.sh

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

PYTHON_BIN="${PYTHON_BIN:-python3}"
VENV_DIR="${VENV_DIR:-.venv}"
MODE="${MODE:-safe}"                       # safe | devbox
OFFLINE="${OFFLINE:-0}"                    # 1 to avoid network-dependent steps
ALLOW_REMOTE_INSTALL="${ALLOW_REMOTE_INSTALL:-0}"  # 1 allows curl|bash installers (not recommended)

# Optional pins (set to enforce repeatability)
RUFF_VER="${RUFF_VER:-}"
MYPY_VER="${MYPY_VER:-}"
PYTEST_VER="${PYTEST_VER:-}"
PIP_AUDIT_VER="${PIP_AUDIT_VER:-}"
PRE_COMMIT_VER="${PRE_COMMIT_VER:-}"
PIP_TOOLS_VER="${PIP_TOOLS_VER:-}"
TYPES_REQUESTS_VER="${TYPES_REQUESTS_VER:-}"

# Optional index configuration (for corp/proxy mirrors)
PIP_INDEX_URL="${PIP_INDEX_URL:-}"
PIP_EXTRA_INDEX_URL="${PIP_EXTRA_INDEX_URL:-}"

# ---------- helpers ----------
die(){ echo "ERROR: $*" >&2; exit 1; }
have(){ command -v "$1" >/dev/null 2>&1; }

if [ "${EUID:-$(id -u)}" -eq 0 ]; then
  die "Do not run as root. Use a normal user. Devbox installs may use sudo."
fi

echo "==> Root: ${ROOT}"
echo "==> Mode: ${MODE}"
echo "==> Offline: ${OFFLINE}"
echo "==> Python: ${PYTHON_BIN}"
echo "==> Venv: ${VENV_DIR}"

$PYTHON_BIN -V >/dev/null 2>&1 || die "python not found (set PYTHON_BIN=python3.X)"

# ---------- create venv ----------
if [ -d "${VENV_DIR}" ] && [ -x "${VENV_DIR}/bin/python" ]; then
  echo "==> Using existing venv: ${VENV_DIR}"
else
  echo "==> Creating venv: ${VENV_DIR}"
  $PYTHON_BIN -m venv "$VENV_DIR"
fi

# shellcheck disable=SC1091
. "${VENV_DIR}/bin/activate"

# ---------- pip config (optional) ----------
if [ -n "${PIP_INDEX_URL}" ]; then export PIP_INDEX_URL; fi
if [ -n "${PIP_EXTRA_INDEX_URL}" ]; then export PIP_EXTRA_INDEX_URL; fi

echo "==> Upgrading packaging toolchain"
python -m pip install -U pip wheel setuptools

# ---------- install toolchain (optionally pinned) ----------
pin_or_latest() {
  local pkg="$1" ver="$2"
  if [ -n "$ver" ]; then
    echo "${pkg}==${ver}"
  else
    echo "${pkg}"
  fi
}

TOOLCHAIN_PKGS=(
  "$(pin_or_latest ruff "${RUFF_VER}")"
  "$(pin_or_latest mypy "${MYPY_VER}")"
  "$(pin_or_latest pytest "${PYTEST_VER}")"
  "$(pin_or_latest pip-audit "${PIP_AUDIT_VER}")"
  "$(pin_or_latest pre-commit "${PRE_COMMIT_VER}")"
  "$(pin_or_latest pip-tools "${PIP_TOOLS_VER}")"
  "$(pin_or_latest types-requests "${TYPES_REQUESTS_VER}")"
)

echo "==> Installing Python toolchain"
python -m pip install -U "${TOOLCHAIN_PKGS[@]}"

# ---------- dependency install (locks preferred) ----------
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

# ---------- optional system tooling (devbox only) ----------
if [ "${MODE}" = "devbox" ]; then
  echo "==> Devbox mode: system tooling allowed (machine mutation possible)"
  if have apt-get; then
    echo "==> Installing Docker CLI + compose plugin (best-effort)"
    sudo apt-get update
    sudo apt-get install -y docker.io docker-compose-plugin || true
  else
    echo "==> apt-get not found; skipping Docker install"
  fi

  if ! have helm; then
    if [ "${ALLOW_REMOTE_INSTALL}" = "1" ]; then
      echo "==> Installing Helm via remote installer (explicitly allowed)"
      echo "WARNING: This is a supply-chain risk. Prefer pinned packages/checksums for production."
      curl -fsSL https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash
    else
      echo "==> Helm not installed. Skipping (safe default)."
      echo "To allow remote install: ALLOW_REMOTE_INSTALL=1 MODE=devbox bash setup_codex_env.sh"
    fi
  fi
else
  echo "==> Safe mode: skipping system package installs (Docker/Helm)"
fi

# ---------- forensics snapshot ----------
echo "==> Forensics snapshot: writing .codex_env_snapshot.txt"
{
  echo "ROOT=${ROOT}"
  echo "MODE=${MODE}"
  echo "OFFLINE=${OFFLINE}"
  echo "PYTHON_BIN=${PYTHON_BIN}"
  echo "VENV_DIR=${VENV_DIR}"
  echo "DATE_UTC=$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
  echo
  echo "python=$(python --version 2>&1)"
  echo "pip=$(python -m pip --version 2>&1)"
  echo "ruff=$(ruff --version 2>&1 || true)"
  echo "mypy=$(mypy --version 2>&1 || true)"
  echo "pytest=$(pytest --version 2>&1 || true)"
  echo "pip-audit=$(pip-audit --version 2>&1 || true)"
  echo "docker=$(docker version 2>&1 || true)"
  echo "docker_compose=$(docker compose version 2>&1 || true)"
  echo "helm=$(helm version --short 2>&1 || true)"
  echo
  echo "pip_freeze:"
  python -m pip freeze || true
} > .codex_env_snapshot.txt

# ---------- sanity checks (non-blocking) ----------
echo "==> Quick sanity (non-blocking)"
ruff check . || true
if [ -d tests ] || ls -1 test* >/dev/null 2>&1; then
  pytest -q || true
fi

# Dependency audit can be network-sensitive
if [ "${OFFLINE}" = "1" ]; then
  echo "==> OFFLINE=1: skipping pip-audit"
else
  pip-audit || true
fi

echo "==> Bootstrap complete."
echo "Next: bash codex_gates.sh"