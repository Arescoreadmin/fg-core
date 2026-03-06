#!/bin/sh
set -eu

echo "[bootstrap] starting"

BASE=/var/lib/frostgate

MISSION=$BASE/mission
STATE=$BASE/state
QUEUE=$BASE/agent_queue
RING_STATE=$BASE/ring/state
RING_MODELS=$BASE/ring/models

# Ensure directories exist
mkdir -p \
  "$MISSION" \
  "$STATE" \
  "$QUEUE" \
  "$RING_STATE" \
  "$RING_MODELS"

# Fix permissions first (important for fresh volumes)
chmod -R 0775 "$BASE" || true
chown -R 0:0 "$BASE" || true

# Create mission envelope safely
touch "$MISSION/envelope.json"
chmod 0664 "$MISSION/envelope.json"

echo "{}" > "$MISSION/envelope.json"

echo "[bootstrap] mission envelope created"

echo "[bootstrap] complete"