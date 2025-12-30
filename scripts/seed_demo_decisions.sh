#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${BASE_URL:-http://127.0.0.1:8000}"
API_KEY="${API_KEY:-${FG_API_KEY:-supersecret}}"
TENANT_ID="${TENANT_ID:-acme-prod}"
SEED_MODE="${SEED_MODE:-spike}"
SOURCES="${SOURCES:-edge-gw,waf,collector}"
QUIET="${QUIET:-0}"

HOT_UNIQUE_ATTACK_IPS="${HOT_UNIQUE_ATTACK_IPS:-18}"
HOT_UNIQUE_NOISE_IPS="${HOT_UNIQUE_NOISE_IPS:-12}"
HOT_REPEAT_ATTACKERS="${HOT_REPEAT_ATTACKERS:-5}"

POST_RETRIES="${POST_RETRIES:-3}"
POST_RETRY_SLEEP_MS="${POST_RETRY_SLEEP_MS:-50}"

SELFTEST="${SELFTEST:-0}"
SELFTEST_DB_PATH="${SELFTEST_DB_PATH:-${FG_SQLITE_PATH:-}}"

# Resolve script path once (prevents weird recursion/path issues)
SCRIPT_PATH="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)/$(basename -- "${BASH_SOURCE[0]}")"

req() { curl -fsS "$@"; }
say() { [[ "$QUIET" == "1" ]] || echo "$@"; }
die() { echo "❌ $*" >&2; exit 1; }

ts_hours_ago() { date -u -d "$1 hours ago" +"%Y-%m-%dT%H:%M:%SZ"; }
ts_mins_ago()  { date -u -d "$1 minutes ago" +"%Y-%m-%dT%H:%M:%SZ"; }

IFS=',' read -r -a SRC_ARR <<< "$SOURCES"
[[ "${#SRC_ARR[@]}" -gt 0 ]] || die "SOURCES empty"

pick_source() {
  local idx=$((RANDOM % ${#SRC_ARR[@]}))
  echo "${SRC_ARR[$idx]}"
}

pick_from() {
  local -n arr=$1
  local n="${#arr[@]}"
  (( n > 0 )) || die "pick_from: empty array '$1'"
  local idx=$((RANDOM % n))
  echo "${arr[$idx]}"
}

build_fresh_pool_198() {
  local n="$1"; local -n out="$2"
  out=()
  local i
  for i in $(seq 1 "$n"); do out+=( "198.51.100.$((30 + i))" ); done
}
build_fresh_pool_203() {
  local n="$1"; local -n out="$2"
  out=()
  local i
  for i in $(seq 1 "$n"); do out+=( "203.0.113.$((30 + i))" ); done
}

sleep_ms() {
  python - <<PY 2>/dev/null || sleep 0.05
import time
time.sleep(${POST_RETRY_SLEEP_MS}/1000.0)
PY
}

post() {
  local payload="$1"
  local attempt=1
  while (( attempt <= POST_RETRIES )); do
    if req "${BASE_URL}/defend" \
      -H "Content-Type: application/json" \
      -H "X-API-Key: ${API_KEY}" \
      -d "${payload}" >/dev/null; then
      return 0
    fi
    attempt=$((attempt + 1))
    sleep_ms
  done
  return 1
}

healthcheck() {
  say "Checking server health..."
  req "${BASE_URL}/health" >/dev/null
  say "✅ Server reachable"
}

INTERNAL_IPS=(
  "10.0.0.20" "10.0.0.21" "10.0.0.22" "10.0.0.23"
  "192.0.2.10" "192.0.2.11" "192.0.2.12" "192.0.2.13"
)

BASE_ATTACK_IPS=(
  "203.0.113.10" "203.0.113.11" "203.0.113.12" "203.0.113.13" "203.0.113.14"
  "198.51.100.66" "198.51.100.67" "198.51.100.68"
)

NOISE_IPS=(
  "198.51.100.20" "198.51.100.21" "198.51.100.22" "198.51.100.23" "198.51.100.24"
  "172.16.0.30" "172.16.0.31" "172.16.0.32"
)

emit_bruteforce() {
  local ts="$1" ip="$2" src="$3" fails="${4:-9}"
  post "$(cat <<JSON
{
  "tenant_id": "${TENANT_ID}",
  "source": "${src}",
  "timestamp": "${ts}",
  "event_type": "auth.bruteforce",
  "event": { "src_ip": "${ip}", "failed_auths": ${fails}, "service": "ssh" }
}
JSON
)" || die "POST /defend failed (bruteforce)"
}

emit_auth_noise() {
  local ts="$1" ip="$2" src="$3" fails="${4:-1}"
  post "$(cat <<JSON
{
  "tenant_id": "${TENANT_ID}",
  "source": "${src}",
  "timestamp": "${ts}",
  "event_type": "auth",
  "event": { "src_ip": "${ip}", "failed_auths": ${fails}, "service": "ssh" }
}
JSON
)" || die "POST /defend failed (auth)"
}

emit_info_heartbeat() {
  local ts="$1" ip="$2" src="$3"
  post "$(cat <<JSON
{
  "tenant_id": "${TENANT_ID}",
  "source": "${src}",
  "timestamp": "${ts}",
  "event_type": "info",
  "event": { "src_ip": "${ip}", "msg": "heartbeat" }
}
JSON
)" || die "POST /defend failed (info)"
}

seed_baseline_7d_excluding_last24h() {
  local per_day_auth="$1" per_day_info="$2" per_day_brute="$3"
  say "Seeding: 7-day baseline (excluding last 24h)..."

  local day
  for day in 7 6 5 4 3 2 1; do
    local base=$((day*24))

    for _ in $(seq 1 "$per_day_auth"); do
      local h=$((base + (RANDOM % 24)))
      local ts src ip
      ts="$(ts_hours_ago "$h")"
      src="$(pick_source)"
      if (( RANDOM % 10 < 8 )); then ip="$(pick_from INTERNAL_IPS)"; else ip="$(pick_from NOISE_IPS)"; fi
      emit_auth_noise "$ts" "$ip" "$src" 1
    done

    for _ in $(seq 1 "$per_day_info"); do
      local h=$((base + (RANDOM % 24)))
      local ts src ip
      ts="$(ts_hours_ago "$h")"
      src="$(pick_source)"
      ip="$(pick_from INTERNAL_IPS)"
      emit_info_heartbeat "$ts" "$ip" "$src"
    done

    for _ in $(seq 1 "$per_day_brute"); do
      local h=$((base + (RANDOM % 24)))
      local ts src ip
      ts="$(ts_hours_ago "$h")"
      src="$(pick_source)"
      ip="$(pick_from BASE_ATTACK_IPS)"
      emit_bruteforce "$ts" "$ip" "$src" 9
    done
  done
}

seed_last_24h() {
  local auth_count="$1" info_count="$2" brute_count="$3"
  local fresh_noise_n="${4:-12}"
  local fresh_attack_n="${5:-10}"

  local -a FRESH_NOISE=()
  local -a FRESH_ATTACK=()
  build_fresh_pool_198 "$fresh_noise_n" FRESH_NOISE
  build_fresh_pool_203 "$fresh_attack_n" FRESH_ATTACK

  say "Seeding: last 24h (excluding last 1h)..."

  for _ in $(seq 1 "$auth_count"); do
    local ts src ip
    ts="$(ts_hours_ago "$((2 + (RANDOM % 22)))")"
    src="$(pick_source)"
    if (( RANDOM % 10 < 6 )); then ip="$(pick_from INTERNAL_IPS)"; else ip="$(pick_from FRESH_NOISE)"; fi
    emit_auth_noise "$ts" "$ip" "$src" 1
  done

  for _ in $(seq 1 "$info_count"); do
    local ts src ip
    ts="$(ts_hours_ago "$((2 + (RANDOM % 22)))")"
    src="$(pick_source)"
    ip="$(pick_from INTERNAL_IPS)"
    emit_info_heartbeat "$ts" "$ip" "$src"
  done

  for _ in $(seq 1 "$brute_count"); do
    local ts src ip
    ts="$(ts_hours_ago "$((2 + (RANDOM % 22)))")"
    src="$(pick_source)"
    if (( RANDOM % 10 < 7 )); then ip="$(pick_from BASE_ATTACK_IPS)"; else ip="$(pick_from FRESH_ATTACK)"; fi
    emit_bruteforce "$ts" "$ip" "$src" 9
  done
}

seed_last_1h() {
  local auth_count="$1" info_count="$2" brute_count="$3"
  local unique_attack_n="${4:-$HOT_UNIQUE_ATTACK_IPS}"
  local unique_noise_n="${5:-$HOT_UNIQUE_NOISE_IPS}"
  say "Seeding: last 1h hot window..."

  local -a HOT_ATTACK_UNIQUES=()
  local -a HOT_NOISE_UNIQUES=()
  build_fresh_pool_203 "$unique_attack_n" HOT_ATTACK_UNIQUES
  build_fresh_pool_198 "$unique_noise_n" HOT_NOISE_UNIQUES

  local -a HOT_REPEATERS=()
  if (( HOT_REPEAT_ATTACKERS > 0 )); then
    local i
    for i in $(seq 1 "$HOT_REPEAT_ATTACKERS"); do
      HOT_REPEATERS+=( "203.0.113.$((200 + i))" )
    done
  fi

  for _ in $(seq 1 "$auth_count"); do
    local mins=$((RANDOM % 60))
    local ts src ip
    ts="$(ts_mins_ago "$mins")"
    src="$(pick_source)"
    if (( RANDOM % 10 < 6 )); then ip="$(pick_from INTERNAL_IPS)"; else ip="$(pick_from HOT_NOISE_UNIQUES)"; fi
    emit_auth_noise "$ts" "$ip" "$src" 1
  done

  for _ in $(seq 1 "$info_count"); do
    local mins=$((RANDOM % 60))
    local ts src ip
    ts="$(ts_mins_ago "$mins")"
    src="$(pick_source)"
    ip="$(pick_from INTERNAL_IPS)"
    emit_info_heartbeat "$ts" "$ip" "$src"
  done

  local spray=$(( brute_count / 2 ))
  local persist=$(( brute_count - spray ))

  local j
  for j in $(seq 1 "$spray"); do
    local mins=$((RANDOM % 60))
    local ts src ip
    ts="$(ts_mins_ago "$mins")"
    src="$(pick_source)"
    ip="$(pick_from HOT_ATTACK_UNIQUES)"
    emit_bruteforce "$ts" "$ip" "$src" 9
  done

  if (( persist > 0 )); then
    if (( ${#HOT_REPEATERS[@]} == 0 )); then HOT_REPEATERS=( "${BASE_ATTACK_IPS[@]}" ); fi
    for j in $(seq 1 "$persist"); do
      local mins=$((RANDOM % 60))
      local ts src ip
      ts="$(ts_mins_ago "$mins")"
      src="$(pick_source)"
      ip="$(pick_from HOT_REPEATERS)"
      emit_bruteforce "$ts" "$ip" "$src" 9
    done
  fi
}

get_trend_flag() {
  req "${BASE_URL}/stats/summary" -H "X-API-Key: ${API_KEY}" \
    | python -c "import sys,json; print(json.load(sys.stdin).get('trend_flag',''))"
}

db_clear_decisions() {
  [[ -n "${SELFTEST_DB_PATH}" ]] || die "SELFTEST_DB_PATH/FG_SQLITE_PATH not set for SELFTEST"
  sqlite3 "${SELFTEST_DB_PATH}" "delete from decisions;"
}

run_selftest() {
  say "Running SELFTEST=1 (spike/steady/drop)..."
  local ok=1

  db_clear_decisions
  SEED_MODE=spike SELFTEST=0 QUIET=1 bash "$SCRIPT_PATH" >/dev/null
  [[ "$(get_trend_flag)" == "spike" ]] || { echo "SELFTEST FAIL: spike"; ok=0; }

  db_clear_decisions
  SEED_MODE=steady SELFTEST=0 QUIET=1 bash "$SCRIPT_PATH" >/dev/null
  [[ "$(get_trend_flag)" == "steady" ]] || { echo "SELFTEST FAIL: steady"; ok=0; }

  db_clear_decisions
  SEED_MODE=drop SELFTEST=0 QUIET=1 bash "$SCRIPT_PATH" >/dev/null
  [[ "$(get_trend_flag)" == "drop" ]] || { echo "SELFTEST FAIL: drop"; ok=0; }

  (( ok == 1 )) || exit 1
  echo "✅ SELFTEST PASS"
  exit 0
}

say "Seeding demo decisions into: ${BASE_URL}"
say "Tenant: ${TENANT_ID}"
say "Mode: ${SEED_MODE}"
say "Sources: ${SOURCES}"
say

healthcheck
say

if [[ "$SELFTEST" == "1" ]]; then
  run_selftest
fi

case "${SEED_MODE}" in
  spike)
    seed_baseline_7d_excluding_last24h 18 6 2
    seed_last_24h 44 12 18 14 10
    seed_last_1h 26 4 46 "$HOT_UNIQUE_ATTACK_IPS" "$HOT_UNIQUE_NOISE_IPS"
    ;;
  steady)
    seed_baseline_7d_excluding_last24h 28 10 2
    seed_last_24h 18 6 1 10 6
    HOT_UNIQUE_ATTACK_IPS=6 HOT_UNIQUE_NOISE_IPS=6 HOT_REPEAT_ATTACKERS=2 \
      seed_last_1h 6 2 4 6 6
    ;;
  drop)
    seed_baseline_7d_excluding_last24h 28 10 2
    seed_last_24h 6 4 0 4 0
    HOT_UNIQUE_ATTACK_IPS=0 HOT_UNIQUE_NOISE_IPS=2 HOT_REPEAT_ATTACKERS=0 \
      seed_last_1h 2 2 0 0 2
    ;;
  *)
    die "Unknown SEED_MODE='${SEED_MODE}'. Use spike|steady|drop."
    ;;
esac

say
say "✅ Seed complete."
say "Now hit:"
say "  curl -fsS ${BASE_URL}/stats -H \"X-API-Key: ${API_KEY}\" | python -m json.tool"
say "  curl -fsS ${BASE_URL}/stats/summary -H \"X-API-Key: ${API_KEY}\" | python -m json.tool"