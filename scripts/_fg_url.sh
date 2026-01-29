#!/usr/bin/env bash
set -euo pipefail
export FG_URL="${FG_URL:-http://127.0.0.1:8000}"
export FG_API_KEY="${FG_API_KEY:?set FG_API_KEY}"
