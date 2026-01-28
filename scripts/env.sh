#!/usr/bin/env bash

fg_admin() {
  if [[ -z "${FG_ADMIN_API_KEY:-}" ]]; then
    echo "FG_ADMIN_API_KEY not set"
    return 1
  fi
  export FG_API_KEY="${FG_ADMIN_API_KEY}"
  echo "[fg] admin key loaded"
}

fg_agent() {
  if [[ -z "${FG_AGENT_API_KEY:-}" ]]; then
    echo "FG_AGENT_API_KEY not set"
    return 1
  fi
  export FG_API_KEY="${FG_AGENT_API_KEY}"
  echo "[fg] agent key loaded"
}
