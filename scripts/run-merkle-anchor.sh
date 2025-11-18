#!/usr/bin/env bash
set -e

cd "$(dirname "${BASH_SOURCE[0]}")/.."

if [ ! -d ".venv" ]; then
  echo "Missing .venv – create it with: python3 -m venv .venv"
  exit 1
fi

source .venv/bin/activate

python -m jobs.merkle-anchor.job || python jobs/merkle-anchor/job.py
