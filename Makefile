# =============================================================================
# FrostGate Core - Makefile (single source of truth)
# =============================================================================

SHELL := /bin/bash
.ONESHELL:
.SHELLFLAGS := -euo pipefail -c
.DELETE_ON_ERROR:

# =============================================================================
# Repo + Python
# =============================================================================

VENV ?= .venv
PY   := $(VENV)/bin/python
PIP  := $(VENV)/bin/pip
export PYTHONPATH := .

PYTEST_ENV := env PYTHONHASHSEED=0 TZ=UTC

# =============================================================================
# Runtime defaults
# =============================================================================

HOST     ?= 127.0.0.1
PORT     ?= 8000
BASE_URL ?= http://$(HOST):$(PORT)

FG_ENV                  ?= dev
FG_SERVICE              ?= frostgate-core
FG_AUTH_ENABLED         ?= 1
FG_API_KEY              ?= supersecret
FG_ENFORCEMENT_MODE     ?= observe
FG_DEV_EVENTS_ENABLED   ?= 0
FG_UI_TOKEN_GET_ENABLED ?= 1

ARTIFACTS_DIR ?= artifacts
STATE_DIR     ?= state

FG_STATE_DIR   ?= $(CURDIR)/$(ARTIFACTS_DIR)
FG_SQLITE_PATH ?= $(FG_STATE_DIR)/frostgate.db

export API_KEY := $(FG_API_KEY)

# =============================================================================
# Central env injector
# =============================================================================

define FG_RUN
FG_ENV="$(FG_ENV)" \
FG_SERVICE="$(FG_SERVICE)" \
FG_AUTH_ENABLED="$(FG_AUTH_ENABLED)" \
FG_API_KEY="$(FG_API_KEY)" \
FG_ENFORCEMENT_MODE="$(FG_ENFORCEMENT_MODE)" \
FG_STATE_DIR="$(FG_STATE_DIR)" \
FG_SQLITE_PATH="$(FG_SQLITE_PATH)" \
FG_DEV_EVENTS_ENABLED="$(FG_DEV_EVENTS_ENABLED)" \
FG_UI_TOKEN_GET_ENABLED="$(FG_UI_TOKEN_GET_ENABLED)" \
FG_BASE_URL="$(BASE_URL)" \
BASE_URL="$(BASE_URL)" \
HOST="$(HOST)" \
PORT="$(PORT)" \
API_KEY="$(FG_API_KEY)"
endef

export FG_HOST    := $(HOST)
export FG_PORT    := $(PORT)
export FG_PIDFILE := $(FG_STATE_DIR)/uvicorn.local.pid
export FG_LOGFILE := $(FG_STATE_DIR)/uvicorn.local.log
export FG_APP     := api.main:app
export FG_PY      := $(PY)

# =============================================================================
# Help
# =============================================================================

.PHONY: help
help:
	@printf "%s\n" \
	"FrostGate Core - Targets" \
	"" \
	"Setup:" \
	"  make venv" \
	"" \
	"CI:" \
	"  make ci" \
	"  make ci-integration" \
	"  make ci-evidence" \
	""

# =============================================================================
# Setup
# =============================================================================

.PHONY: venv
venv:
	test -d "$(VENV)" || python -m venv "$(VENV)"
	"$(PIP)" install --upgrade pip
	"$(PIP)" install -r requirements.txt -r requirements-dev.txt

# =============================================================================
# Guards / audits
# =============================================================================

.PHONY: guard-scripts fg-audit-make fg-contract fg-compile

guard-scripts:
	@$(PY) scripts/guard_no_paste_garbage.py
	@$(PY) scripts/guard_makefile_sanity.py

fg-audit-make: guard-scripts
	@$(PY) scripts/audit_make_targets.py

fg-contract: guard-scripts
	@$(PY) scripts/contract_lint.py

fg-compile: guard-scripts
	@$(PY) -m py_compile api/main.py api/feed.py api/ui.py api/dev_events.py api/auth_scopes.py

# =============================================================================
# Lint
# =============================================================================

.PHONY: fg-lint
fg-lint:
	@$(PY) -m py_compile api/middleware/auth_gate.py
	@$(PY) -m ruff check api tests
	@$(PY) -m ruff format --check api tests

# =============================================================================
# Fast lane
# =============================================================================

.PHONY: fg-fast
fg-fast: fg-audit-make fg-contract fg-compile
	@$(PYTEST_ENV) $(PY) -m pytest -q
	@$(MAKE) -s fg-lint

# =============================================================================
# Live port guard
# =============================================================================

.PHONY: fg-live-port-check
fg-live-port-check:
	@$(PY) scripts/fg_port_check.py "$(HOST)" "$(PORT)"

# =============================================================================
# Local server
# =============================================================================

.PHONY: fg-up fg-down fg-ready fg-health fg-logs

fg-up: fg-live-port-check
	mkdir -p "$(FG_STATE_DIR)" "$(STATE_DIR)"
	$(FG_RUN) ./scripts/uvicorn_local.sh start
	$(MAKE) -s fg-ready

fg-down:
	$(FG_RUN) ./scripts/uvicorn_local.sh stop || true

fg-ready:
	@$(FG_RUN) ./scripts/uvicorn_local.sh check

fg-health:
	@curl -fsS "$(BASE_URL)/health" | $(PY) -m json.tool

fg-logs:
	@$(FG_RUN) ./scripts/uvicorn_local.sh logs $(or $(N),200)

# =============================================================================
# Integration tests
# =============================================================================

.PHONY: test-integration
test-integration:
	@test -n "$${BASE_URL:-}" || (echo "❌ BASE_URL is required" && exit 1)
	@test -n "$${FG_SQLITE_PATH:-}" || (echo "❌ FG_SQLITE_PATH is required" && exit 1)
	@test -n "$${FG_API_KEY:-}" || (echo "❌ FG_API_KEY is required" && exit 1)
	@FG_BASE_URL="$${BASE_URL}" $(PYTEST_ENV) $(PY) -m pytest -q -m integration || rc=$$?; \
	if [ "$$rc" -eq 5 ]; then echo "⚠️  No integration tests collected (ok for now)"; exit 0; fi; \
	exit "$$rc"

# =============================================================================
# ITest harness
# =============================================================================

ITEST_HOST     ?= 127.0.0.1
ITEST_PORT     ?= 8001
ITEST_BASE_URL ?= http://$(ITEST_HOST):$(ITEST_PORT)
ITEST_DB       ?= $(CURDIR)/$(STATE_DIR)/frostgate-itest.db
ITEST_WIPE_DB  ?= 1

.PHONY: itest-db-reset itest-up itest-down itest-local

itest-db-reset:
	@set -euo pipefail; \
	mkdir -p "$(STATE_DIR)"; \
	if [ "$(ITEST_WIPE_DB)" = "1" ]; then rm -f "$(ITEST_DB)"; fi; \
	FG_SQLITE_PATH="$(ITEST_DB)" $(PY) -c "from api.db import init_db; init_db()"; \
	echo "✅ itest db ready: $(ITEST_DB)"

itest-down:
	@set -euo pipefail; \
	$(MAKE) -s fg-down HOST="$(ITEST_HOST)" PORT="$(ITEST_PORT)" BASE_URL="$(ITEST_BASE_URL)" \
	FG_SQLITE_PATH="$(ITEST_DB)" FG_API_KEY="$(FG_API_KEY)" FG_AUTH_ENABLED="$(FG_AUTH_ENABLED)" \
	>/dev/null 2>&1 || true

itest-up: itest-db-reset
	@set -euo pipefail; \
	$(MAKE) -s fg-up HOST="$(ITEST_HOST)" PORT="$(ITEST_PORT)" BASE_URL="$(ITEST_BASE_URL)" \
	FG_SQLITE_PATH="$(ITEST_DB)" FG_API_KEY="$(FG_API_KEY)" FG_AUTH_ENABLED="$(FG_AUTH_ENABLED)"

itest-local: itest-down itest-up
	@set -euo pipefail; \
	trap '$(MAKE) -s itest-down >/dev/null 2>&1 || true' EXIT; \
	BASE_URL="$(ITEST_BASE_URL)" FG_API_KEY="$(FG_API_KEY)" FG_SQLITE_PATH="$(ITEST_DB)" ./scripts/smoke_auth.sh; \
	BASE_URL="$(ITEST_BASE_URL)" FG_API_KEY="$(FG_API_KEY)" FG_SQLITE_PATH="$(ITEST_DB)" $(MAKE) -s test-integration

# =============================================================================
# CI lanes
# =============================================================================

.PHONY: ci ci-integration ci-evidence

ci: venv fg-fast

ci-integration: venv itest-local

# =============================================================================
# Evidence
# =============================================================================

EVIDENCE_SCENARIO ?= $(or $(SCENARIO),spike)

.PHONY: evidence
evidence:
	@set -euo pipefail; \
	test -n "$${BASE_URL:-}" || exit 1; \
	test -n "$${FG_API_KEY:-}" || exit 1; \
	test -n "$${FG_SQLITE_PATH:-}" || exit 1; \
	mkdir -p "$(ARTIFACTS_DIR)" "$(STATE_DIR)" keys; \
	ts="$$(date -u +%Y%m%dT%H%M%SZ)"; \
	out="$(ARTIFACTS_DIR)/evidence_$${ts}_$${EVIDENCE_SCENARIO}"; \
	mkdir -p "$$out"; \
	git rev-parse HEAD > "$$out/git_head.txt"; \
	git status --porcelain=v1 > "$$out/git_status.txt" || true; \
	curl -fsS "$${BASE_URL}/health" > "$$out/health.json"; \
	curl -fsS "$${BASE_URL}/openapi.json" > "$$out/openapi.json"; \
	( cd "$$out" && find . -type f -print0 | sort -z | xargs -0 sha256sum > manifest.sha256 )

ci-evidence: venv itest-local
	@SCENARIO="$${SCENARIO:-spike}" BASE_URL="$(ITEST_BASE_URL)" FG_API_KEY="$(FG_API_KEY)" \
	FG_SQLITE_PATH="$(ITEST_DB)" $(MAKE) -s evidence
