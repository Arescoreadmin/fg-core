#!/usr/bin/env bash
set -euo pipefail

PY="${PY:-python}"
RUFF="${RUFF:-$PY -m ruff}"

TARGETS=("api" "tests" "scripts")

echo "== ruff check --fix (lint autofix) =="
$RUFF check --fix "${TARGETS[@]}"

echo "== ruff format (autoformat) =="
$RUFF format "${TARGETS[@]}"

echo "== ruff check (verify) =="
$RUFF check "${TARGETS[@]}"

echo "== ruff format --check (verify) =="
$RUFF format --check "${TARGETS[@]}"

echo "Done. Your formatter has been appeased."
