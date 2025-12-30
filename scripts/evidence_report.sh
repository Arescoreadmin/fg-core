#!/usr/bin/env bash
set -euo pipefail
trap 'echo "FAILED at line $LINENO"; exit 1' ERR

: "${BASE_URL:?BASE_URL required}"
: "${FG_API_KEY:?FG_API_KEY required}"
: "${FG_SQLITE_PATH:?FG_SQLITE_PATH required}"

: "${FG_AUTH_ENABLED:=1}"
: "${FG_ENFORCEMENT_MODE:=observe}"
: "${ARTIFACTS_DIR:=artifacts}"
: "${EVIDENCE_DIR:=${ARTIFACTS_DIR}/evidence}"
: "${SCENARIO:=spike}"
: "${HOST:=127.0.0.1}"
: "${PORT:=8001}"
: "${FG_VERBOSE:=0}"

mkdir -p "${ARTIFACTS_DIR}" "${EVIDENCE_DIR}"

ts="$(date -u +%Y%m%dT%H%M%SZ)"
scenario_clean="$(printf "%s" "${SCENARIO}" | tr -d '[:space:]')"
out="${EVIDENCE_DIR}/${ts}_${scenario_clean}"
mkdir -p "${out}"

sqlite_abs="$(python - <<'PY'
import os
print(os.path.abspath(os.environ["FG_SQLITE_PATH"]))
PY
)"

fail_auth() {
  echo "❌ Auth failed calling: $1" >&2
  echo "   BASE_URL=${BASE_URL}" >&2
  echo "   FG_AUTH_ENABLED=${FG_AUTH_ENABLED}" >&2
  echo "   FG_API_KEY=[set]" >&2
  exit 1
}

curl_json() {
  local url="$1"
  local outfile="$2"
  local auth="${3:-0}"

  if [ "${auth}" = "1" ]; then
    local code
    code="$(curl -sS -o "${outfile}.tmp" -w "%{http_code}" -H "X-API-Key: ${FG_API_KEY}" "${url}" || true)"
    if [ "${code}" != "200" ]; then
      rm -f "${outfile}.tmp" || true
      if [ "${code}" = "401" ] || [ "${code}" = "403" ]; then
        fail_auth "${url}"
      fi
      echo "❌ Request failed (${code}): ${url}" >&2
      exit 1
    fi
  else
    curl -fsS "${url}" > "${outfile}.tmp"
  fi

  python -m json.tool < "${outfile}.tmp" > "${outfile}"
  rm -f "${outfile}.tmp"
}

{
  echo "timestamp=${ts}"
  echo "scenario=${scenario_clean}"
  echo "base_url=${BASE_URL}"
  echo "sqlite_path=${sqlite_abs}"
  echo "git_commit=$(git rev-parse HEAD 2>/dev/null || true)"
  echo "uname=$(uname -a 2>/dev/null || true)"
  echo "python=$(python -V 2>/dev/null || true)"
} > "${out}/meta.txt"

curl_json "${BASE_URL}/health"        "${out}/health.json"        0
curl_json "${BASE_URL}/stats/summary" "${out}/stats_summary.json" 1
curl_json "${BASE_URL}/stats/debug"   "${out}/stats_debug.json"   1

(git rev-parse HEAD 2>/dev/null || true) > "${out}/git_commit.txt"
(git status --porcelain=v1 2>/dev/null || true) > "${out}/git_status.txt"
(find . -maxdepth 3 -type d -not -path "./.git/*" | sort) > "${out}/tree_dirs_max3.txt"

cat > "${out}/config.env" <<EOF
FG_ENV=${FG_ENV:-dev}
FG_AUTH_ENABLED=${FG_AUTH_ENABLED}
FG_ENFORCEMENT_MODE=${FG_ENFORCEMENT_MODE}
FG_SQLITE_PATH=${sqlite_abs}
HOST=${HOST}
PORT=${PORT}
BASE_URL=${BASE_URL}
EOF

if [ -f "${sqlite_abs}" ]; then
  sha256sum "${sqlite_abs}" > "${out}/sqlite.sha256"
else
  echo "missing sqlite db" > "${out}/sqlite.sha256"
fi

(
  cd "${out}"
  find . -type f \
    ! -name 'manifest.sha256' \
    ! -name 'manifest.sha256.minisig' \
    -print0 | sort -z | xargs -0 sha256sum > manifest.sha256
)

echo "${out}" > "${ARTIFACTS_DIR}/latest_evidence_dir.txt"

if [ "${FG_VERBOSE}" = "1" ]; then
  echo "Evidence directory: ${out}"
  ls -lah "${out}"
fi

echo "✅ Evidence report: ${out}"
