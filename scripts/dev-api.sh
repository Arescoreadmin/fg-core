#!/usr/bin/env bash
set -e

cd "$(dirname "${BASH_SOURCE[0]}")/.."

if [ ! -d ".venv" ]; then
  echo "Missing .venv – create with: python3 -m venv .venv"
  exit 1
fi

source .venv/bin/activate
uvicorn api.main:app --host 0.0.0.0 --port 8080 --reload
