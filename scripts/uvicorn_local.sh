#!/usr/bin/env bash
set -euo pipefail

HOST="${FG_HOST:-127.0.0.1}"
PORT="${FG_PORT:-8000}"

PIDFILE="${FG_PIDFILE:-artifacts/uvicorn.local.pid}"
LOGFILE="${FG_LOGFILE:-artifacts/uvicorn.local.log}"

APP="${FG_APP:-api.main:app}"
PY="${FG_PY:-.venv/bin/python}"

BASE_URL="${FG_BASE_URL:-http://${HOST}:${PORT}}"
READY_PATH="${FG_READY_PATH:-/health/ready}"
HEALTH_PATH="${FG_HEALTH_PATH:-/health}"

READY_REQUIRED="${FG_READY_REQUIRED:-1}"
RESTART_IF_RUNNING="${FG_RESTART_IF_RUNNING:-0}"

START_TIMEOUT_SEC="${FG_START_TIMEOUT_SEC:-10}"
READY_TIMEOUT_SEC="${FG_READY_TIMEOUT_SEC:-10}"
STOP_TIMEOUT_SEC="${FG_STOP_TIMEOUT_SEC:-8}"
POLL_INTERVAL_SEC="${FG_POLL_INTERVAL_SEC:-0.1}"

FORCE="${FG_FORCE:-0}"
STRICT="${FG_STRICT_START:-0}"

FG_EXTRA_UVICORN_ARGS="${FG_EXTRA_UVICORN_ARGS:-}"

mkdir -p "$(dirname "$PIDFILE")" "$(dirname "$LOGFILE")"

_now_ms() {
  "$PY" - <<'PY' 2>/dev/null || date +%s%3N
import time
print(int(time.time()*1000))
PY
}

_read_pidfile() {
  [[ -f "$PIDFILE" ]] || return 1
  local pid
  pid="$(cat "$PIDFILE" 2>/dev/null || true)"
  [[ -n "${pid:-}" ]] || return 1
  echo "$pid"
}

_pid_alive() { kill -0 "$1" 2>/dev/null; }

_port_owner_pid() {
  ss -lptn "sport = :$PORT" 2>/dev/null \
    | awk -F'pid=' 'NR==2{print $2}' \
    | awk -F',' '{print $1}' \
    | tr -d '[:space:]' \
    | head -n 1
}

_wait_for_port_free() {
  local deadline_ms="$(( $(_now_ms) + STOP_TIMEOUT_SEC*1000 ))"
  while (( $(_now_ms) < deadline_ms )); do
    local opid
    opid="$(_port_owner_pid || true)"
    [[ -z "${opid:-}" ]] && return 0
    sleep "$POLL_INTERVAL_SEC"
  done
  return 1
}

_auth_header() {
  local auth="${FG_AUTH_ENABLED:-}"
  local key="${FG_API_KEY:-}"
  if [[ "${auth}" == "1" && -n "${key}" ]]; then
    printf 'X-API-Key: %s' "$key"
  fi
}

_curl_ok() {
  local url="$1"
  local hdr
  hdr="$(_auth_header || true)"
  local args=( -fsS )
  [[ -n "${hdr:-}" ]] && args+=( -H "$hdr" )
  args+=( "$url" )
  curl "${args[@]}" >/dev/null 2>&1
}

_curl_code() {
  local url="$1"
  local hdr
  hdr="$(_auth_header || true)"
  local args=( -sS -o /dev/null -w "%{http_code}" )
  [[ -n "${hdr:-}" ]] && args+=( -H "$hdr" )
  args+=( "$url" )
  curl "${args[@]}" || true
}

_curl_body() {
  local url="$1"
  local hdr
  hdr="$(_auth_header || true)"
  local args=( -sS )
  [[ -n "${hdr:-}" ]] && args+=( -H "$hdr" )
  args+=( "$url" )
  curl "${args[@]}" || true
}

_wait_for_health() {
  local deadline_ms="$(( $(_now_ms) + START_TIMEOUT_SEC*1000 ))"
  while (( $(_now_ms) < deadline_ms )); do
    if _curl_ok "${BASE_URL}${HEALTH_PATH}"; then
      echo "✅ ${HEALTH_PATH} is up at ${BASE_URL}"
      return 0
    fi
    sleep "$POLL_INTERVAL_SEC"
  done

  echo "❌ Uvicorn did not become reachable at ${BASE_URL}${HEALTH_PATH} within ${START_TIMEOUT_SEC}s" >&2
  echo "---- last logs ----" >&2
  tail -n 200 "$LOGFILE" 2>/dev/null || true
  return 1
}

_ready_code() { _curl_code "${BASE_URL}${READY_PATH}"; }
_ready_body() { _curl_body "${BASE_URL}${READY_PATH}"; }

_wait_for_ready_200() {
  local deadline_ms="$(( $(_now_ms) + READY_TIMEOUT_SEC*1000 ))"
  while (( $(_now_ms) < deadline_ms )); do
    local code
    code="$(_ready_code)"
    [[ "$code" == "200" ]] && echo "✅ ${READY_PATH} OK" && return 0
    sleep "$POLL_INTERVAL_SEC"
  done

  echo "❌ Timed out waiting for ${READY_PATH} to return 200 (timeout ${READY_TIMEOUT_SEC}s)" >&2
  echo "---- ready body ----" >&2
  _ready_body >&2 || true
  echo "---- last logs ----" >&2
  tail -n 200 "$LOGFILE" 2>/dev/null || true
  return 1
}

_ready_check_informational() {
  local code
  code="$(_ready_code)"
  if [[ "$code" == "200" ]]; then
    echo "✅ ${READY_PATH} OK"
  elif [[ "$code" == "503" ]]; then
    echo "⚠️  ${READY_PATH} not ready yet (503) but server is up"
  else
    echo "⚠️  ${READY_PATH} returned ${code} (ignored)"
  fi
  return 0
}

_clean_stale_pidfile_if_needed() {
  if [[ -f "$PIDFILE" ]]; then
    local pid
    pid="$(_read_pidfile || true)"
    if [[ -n "${pid:-}" ]] && ! _pid_alive "$pid"; then
      echo "⚠️  Stale pidfile: $PIDFILE points to dead pid=$pid. Removing."
      rm -f "$PIDFILE"
    fi
  fi
}

is_running() {
  _clean_stale_pidfile_if_needed
  local pid
  pid="$(_read_pidfile || true)"
  [[ -n "${pid:-}" ]] || return 1
  _pid_alive "$pid"
}

_precreate_sqlite_file() {
  local p="${FG_SQLITE_PATH:-}"
  [[ -z "${p:-}" ]] && return 0
  mkdir -p "$(dirname "$p")" 2>/dev/null || true
  touch "$p" 2>/dev/null || true
}

_apply_default_env() {
  export FG_ENV="${FG_ENV:-dev}"
  export FG_SERVICE="${FG_SERVICE:-frostgate-core}"
  export FG_AUTH_ENABLED="${FG_AUTH_ENABLED:-1}"
  export FG_API_KEY="${FG_API_KEY:?set FG_API_KEY}"
  export FG_ENFORCEMENT_MODE="${FG_ENFORCEMENT_MODE:-observe}"
  export FG_STATE_DIR="${FG_STATE_DIR:-$(pwd)/artifacts}"
  export FG_SQLITE_PATH="${FG_SQLITE_PATH:-$(pwd)/artifacts/frostgate.db}"
  export FG_DEV_EVENTS_ENABLED="${FG_DEV_EVENTS_ENABLED:-0}"
FG_UI_TOKEN_GET_ENABLED="${FG_UI_TOKEN_GET_ENABLED:-0}"
  export FG_BASE_URL="${FG_BASE_URL:-$BASE_URL}"

  export BASE_URL="${BASE_URL:-$BASE_URL}"
  export HOST="${HOST:-$HOST}"
  export PORT="${PORT:-$PORT}"
  export API_KEY="${API_KEY:-$FG_API_KEY}"
}

start() {
  _clean_stale_pidfile_if_needed
  _apply_default_env

  if is_running; then
    if [[ "$STRICT" == "1" ]]; then
      echo "❌ uvicorn already running (pid=$(_read_pidfile)); strict mode refuses reuse" >&2
      exit 1
    fi
    if [[ "$RESTART_IF_RUNNING" == "1" ]]; then
      echo "⚠️  uvicorn already running (pid=$(_read_pidfile)); restarting to apply env"
      stop
    else
      echo "✅ uvicorn already running (pid=$(_read_pidfile))"
      exit 0
    fi
  fi

  local opid
  opid="$(_port_owner_pid || true)"
  if [[ -n "${opid:-}" ]]; then
    if [[ "$FORCE" == "1" ]]; then
      echo "⚠️  Port $PORT owned by pid=$opid. FG_FORCE=1 set, terminating."
      kill "$opid" 2>/dev/null || true
      if ! _wait_for_port_free; then
        echo "⚠️  Port still owned after grace. SIGKILL pid=$opid"
        kill -9 "$opid" 2>/dev/null || true
        _wait_for_port_free || true
      fi
    else
      echo "❌ Port $PORT is already in use by pid=$opid. Stop that process first (or set FG_FORCE=1)." >&2
      exit 1
    fi
  fi

  rm -f "$PIDFILE"
  _precreate_sqlite_file

  local -a uv_args
  uv_args=( -m uvicorn "$APP" --host "$HOST" --port "$PORT" )
  if [[ -n "${FG_EXTRA_UVICORN_ARGS:-}" ]]; then
    # shellcheck disable=SC2206
    uv_args+=( ${FG_EXTRA_UVICORN_ARGS} )
  fi

  nohup "$PY" "${uv_args[@]}" >"$LOGFILE" 2>&1 &
  echo $! >"$PIDFILE"

  echo "✅ Started uvicorn (pid=$(_read_pidfile)) -> ${HOST}:${PORT}"

  _wait_for_health
  if [[ "$READY_REQUIRED" == "1" ]]; then
    _wait_for_ready_200
  else
    _ready_check_informational
  fi
}

stop() {
  _clean_stale_pidfile_if_needed

  if [[ ! -f "$PIDFILE" ]]; then
    echo "✅ uvicorn not running (no pidfile)"
    return 0
  fi

  local pid
  pid="$(_read_pidfile || true)"
  if [[ -z "${pid:-}" ]]; then
    rm -f "$PIDFILE"
    echo "✅ uvicorn not running (empty pidfile)"
    return 0
  fi

  _pid_alive "$pid" && kill "$pid" 2>/dev/null || true

  local deadline_ms="$(( $(_now_ms) + STOP_TIMEOUT_SEC*1000 ))"
  while (( $(_now_ms) < deadline_ms )); do
    ! _pid_alive "$pid" && break
    sleep "$POLL_INTERVAL_SEC"
  done

  if _pid_alive "$pid"; then
    echo "⚠️  pid=$pid still alive after ${STOP_TIMEOUT_SEC}s, SIGKILL"
    kill -9 "$pid" 2>/dev/null || true
  fi

  rm -f "$PIDFILE"
  _wait_for_port_free || true
  echo "✅ Stopped uvicorn"
}

restart() { stop; start; }

status() {
  if is_running; then
    echo "✅ running pid=$(_read_pidfile)"
    exit 0
  fi
  echo "❌ not running"
  exit 1
}

logs() { tail -n "${1:-200}" "$LOGFILE"; }

server_check() {
  if ! _curl_ok "${BASE_URL}${HEALTH_PATH}"; then
    echo "❌ ${HEALTH_PATH} not reachable at ${BASE_URL}" >&2
    echo "---- last logs ----" >&2
    tail -n 120 "$LOGFILE" 2>/dev/null || true
    return 1
  fi

  if [[ "$READY_REQUIRED" == "1" ]]; then
    local code
    code="$(_ready_code)"
    if [[ "$code" != "200" ]]; then
      echo "❌ ${READY_PATH} expected 200 but got ${code}" >&2
      echo "---- ready body ----" >&2
      _ready_body >&2 || true
      return 1
    fi
    echo "✅ ready"
  else
    _ready_check_informational
  fi
  return 0
}

case "${1:-}" in
  start) start ;;
  stop) stop ;;
  restart) restart ;;
  status) status ;;
  logs) shift; logs "${1:-200}" ;;
  env) _apply_default_env; env | rg '^(FG_|BASE_URL=|API_KEY=|HOST=|PORT=)' || true ;;
  check) server_check ;;
  *)
    echo "Usage: $0 {start|stop|restart|status|logs [N]|env|check}"
    exit 2
    ;;
esac
