#!/bin/sh
set -eu

echo "[bootstrap] starting"

# Only create directories that are volume-backed in this container.
mkdir -p \
  /var/lib/frostgate/mission \
  /var/lib/frostgate/state \
  /var/lib/frostgate/agent_queue \
  /var/lib/frostgate/ring/state \
  /var/lib/frostgate/ring/models

# Create mission envelope if missing
if [ ! -f /var/lib/frostgate/mission/envelope.json ]; then
  ts="$(date -u +%FT%TZ)"
  printf '%s\n' "{\"version\":1,\"generated_by\":\"compose-bootstrap\",\"ts\":\"${ts}\",\"resources\":[]}" \
    > /var/lib/frostgate/mission/envelope.json
  echo "[bootstrap] wrote /var/lib/frostgate/mission/envelope.json"
else
  echo "[bootstrap] mission envelope already present"
fi

ls -lah /var/lib/frostgate/mission || true
echo "[bootstrap] done"
