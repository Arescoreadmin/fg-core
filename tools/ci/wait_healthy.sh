#!/usr/bin/env bash
set -euo pipefail

name="${1:?container name required}"
seconds="${2:-30}"

timeout "${seconds}" bash -lc "
  until [ \"\$(docker inspect -f '{{.State.Health.Status}}' ${name} 2>/dev/null)\" = 'healthy' ]; do
    sleep 1
  done
"