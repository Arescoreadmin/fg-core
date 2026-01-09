#!/usr/bin/env bash
set -euo pipefail

# FrostGate Core: drift-proof snapshot bundle
# Usage:
#   bash scripts/fg_snapshot_bundle.sh
#   FAST=1 bash scripts/fg_snapshot_bundle.sh     # skip heavy stuff (doctor/tests)
#   OUTDIR=artifacts bash scripts/fg_snapshot_bundle.sh

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

OUTROOT="${OUTDIR:-artifacts}"
TS="$(date -u +"%Y%m%dT%H%M%SZ")"
SNAP_DIR="${OUTROOT}/snapshot_${TS}"
mkdir -p "$SNAP_DIR"

run() {
  local name="$1"; shift
  {
    echo "\$ $*"
    echo
    "$@"
  } > "${SNAP_DIR}/${name}" 2>&1 || {
    echo "Command failed (captured): $*" >> "${SNAP_DIR}/${name}"
    return 0
  }
}

# --- Git truth ---
run 00_pwd.txt              pwd
run 01_git_remote.txt       git remote -v
run 02_git_branch.txt       bash -lc 'git rev-parse --abbrev-ref HEAD && git rev-parse HEAD'
run 03_git_status.txt       git status --porcelain=v1
run 04_git_status_full.txt  git status
run 05_git_log_20.txt       bash -lc 'git --no-pager log -20 --decorate --oneline'
run 06_git_diff_stat.txt    bash -lc 'git --no-pager diff --stat'
run 07_git_diff.txt         bash -lc 'git --no-pager diff'

# --- Repo structure (3 levels, readable) ---
run 10_tree_3levels.txt bash -lc 'find . -maxdepth 3 -type d \
  -not -path "./.git*" -not -path "./.venv*" -not -path "./artifacts*" -not -path "./state*" \
  | sed "s|^\./||" | sort'

run 11_files_top.txt bash -lc 'ls -la'

# --- Key config + CI files (copy, don’t “interpret”) ---
copy_file() {
  local f="$1"
  if [[ -f "$f" ]]; then
    mkdir -p "${SNAP_DIR}/files/$(dirname "$f")"
    cp -a "$f" "${SNAP_DIR}/files/$f"
  fi
}

copy_file Makefile
copy_file pytest.ini
copy_file pyproject.toml
copy_file requirements.txt
copy_file requirements-dev.txt
copy_file CONTRACT.md
copy_file README.md
copy_file .github/workflows/ci.yml
copy_file .github/workflows/docker-ci.yml
copy_file .github/workflows/release-images.yml

# Grab scripts + api surface quickly (but not your entire universe)
mkdir -p "${SNAP_DIR}/files/scripts" "${SNAP_DIR}/files/api"
bash -lc 'ls -1 scripts 2>/dev/null || true' > "${SNAP_DIR}/scripts_index.txt"
bash -lc 'ls -1 api 2>/dev/null || true' > "${SNAP_DIR}/api_index.txt"

# Store selected scripts that matter for “drift prevention”
for f in \
  scripts/snapshot_context.sh \
  scripts/snapshot_all.sh \
  scripts/guard_no_paste_garbage.py \
  scripts/guard_makefile_sanity.py \
  scripts/guard_pytest_ini.py \
  scripts/find_bad_toml.py \
  scripts/harden_not_mounted_tests.py \
  scripts/write_file.py \
  scripts/audit_make_targets.py \
  scripts/contract_lint.py \
  scripts/uvicorn_local.sh \
; do
  copy_file "$f"
done

# --- Local health checks ---
if [[ "${FAST:-0}" != "1" ]]; then
  run 20_make_doctor.txt make doctor
  run 21_make_ci.txt     make ci
else
  run 20_make_doctor.txt bash -lc 'echo "FAST=1: skipped make doctor"'
  run 21_make_ci.txt     bash -lc 'echo "FAST=1: skipped make ci"'
fi

# --- If GitHub CLI exists, capture workflow run list (works even for private repos) ---
if command -v gh >/dev/null 2>&1; then
  run 30_gh_repo_view.txt  gh repo view --json nameWithOwner,defaultBranchRef,visibility
  run 31_gh_run_list.txt   bash -lc 'gh run list --limit 20 || true'
  run 32_gh_workflows.txt  bash -lc 'gh workflow list || true'
else
  echo "gh not installed; skipping GH run snapshot" > "${SNAP_DIR}/30_gh_repo_view.txt"
fi

# --- Bundle it ---
TARBALL="${OUTROOT}/snapshot_${TS}.tar.gz"
tar -czf "$TARBALL" -C "$OUTROOT" "snapshot_${TS}"

cat > "${SNAP_DIR}/HOW_TO_USE_IN_NEW_CHAT.md" <<EOF
# FrostGate snapshot ${TS}

Attach/paste these in the new chat:
- ${SNAP_DIR}/00_pwd.txt
- ${SNAP_DIR}/02_git_branch.txt
- ${SNAP_DIR}/03_git_status.txt
- ${SNAP_DIR}/05_git_log_20.txt
- ${SNAP_DIR}/06_git_diff_stat.txt (and 07 if needed)
- ${SNAP_DIR}/20_make_doctor.txt
- ${SNAP_DIR}/21_make_ci.txt
- files/.github/workflows/ci.yml
- files/Makefile
- files/pytest.ini

Tarball: ${TARBALL}
EOF

echo "✅ Snapshot dir: ${SNAP_DIR}"
echo "✅ Snapshot tarball: ${TARBALL}"
echo "➡ Next: open ${SNAP_DIR}/HOW_TO_USE_IN_NEW_CHAT.md"
