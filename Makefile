# =============================================================================
# FrostGate Core - Makefile
# production-grade / single source of truth / no drift
# =============================================================================

SHELL := /bin/bash
.ONESHELL:
.SHELLFLAGS := -euo pipefail -c
.DELETE_ON_ERROR:

# -----------------------------------------------------------------------------
# Repo + Python
# -----------------------------------------------------------------------------
VENV   ?= .venv
PY     ?= $(VENV)/bin/python
PIP    ?= $(VENV)/bin/pip
export PYTHONPATH := .

# -----------------------------------------------------------------------------
# Runtime defaults (single source of truth)
# -----------------------------------------------------------------------------
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

# Integration defaults (kept separate on purpose)
ITEST_HOST ?= 127.0.0.1
ITEST_PORT ?= 8001
ITEST_BASE_URL ?= http://$(ITEST_HOST):$(ITEST_PORT)
ITEST_DB ?= $(CURDIR)/state/frostgate-itest.db

# State / artifacts
ARTIFACTS_DIR ?= artifacts
STATE_DIR     ?= state

# Canonical state dir for local runs (logs, pid, db)
FG_STATE_DIR   ?= $(CURDIR)/$(ARTIFACTS_DIR)
FG_SQLITE_PATH ?= $(FG_STATE_DIR)/frostgate.db

# Legacy mirror (some scripts/tests read API_KEY)
export API_KEY := $(FG_API_KEY)

# -----------------------------------------------------------------------------
# Centralized env injector (single source of truth)
# Use: $(FG_RUN) <command>
# -----------------------------------------------------------------------------
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

# -----------------------------------------------------------------------------
# Uvicorn wrapper integration (pid-safe, log-safe)
# scripts/uvicorn_local.sh expects these
# -----------------------------------------------------------------------------
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
	  "Fast gates (no server):" \
	  "  make fg-audit-make      Makefile target collision audit" \
	  "  make fg-contract        Contract linter" \
	  "  make fg-compile         py_compile core entrypoints" \
	  "  make fg-fast            audit + contract + compile + unit tests" \
	  "" \
	  "Local server:" \
	  "  make fg-up              start uvicorn (pid+log under artifacts/)" \
	  "  make fg-down            stop uvicorn" \
	  "  make fg-restart         restart uvicorn + wait for ready" \
	  "  make fg-ready           wait /health/ready" \
	  "  make fg-health          GET /health" \
	  "  make fg-logs N=200       tail uvicorn log" \
	  "  make fg-openapi-assert  assert key OpenAPI paths exist" \
	  "" \
	  "Integration:" \
	  "  make itest-local        spins API on :8001, runs smoke_auth + integration tests" \
	  "" \
	  "No drift:" \
	  "  make no-drift           guard + itest-local + unit + git-clean check" \
	  "" \
	  "CI:" \
	  "  make ci                 opinionated fast CI lane" \
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
# Guardrails / audits
# =============================================================================
.PHONY: fg-audit-make fg-contract fg-compile
fg-audit-make:
	@./scripts/audit_make_targets.py

fg-contract:
	@./scripts/contract_lint.py

fg-compile:
	@$(PY) -m py_compile api/main.py api/feed.py api/ui.py api/dev_events.py api/auth_scopes.py

# =============================================================================
# Fast lane (no server)
# =============================================================================
.PHONY: fg-fast fg-check fg-test
fg-fast: fg-audit-make fg-contract fg-compile
	@$(PY) -m pytest -q

fg-check: fg-fast
fg-test: fg-fast

# =============================================================================
# Local server (canonical)
# =============================================================================
.PHONY: fg-up fg-down fg-restart fg-ready fg-health fg-logs fg-status

fg-up:
	mkdir -p "$(FG_STATE_DIR)" "$(STATE_DIR)"
	$(FG_RUN) ./scripts/uvicorn_local.sh start
	$(MAKE) -s fg-ready

fg-down:
	$(FG_RUN) ./scripts/uvicorn_local.sh stop || true

fg-restart:
	mkdir -p "$(FG_STATE_DIR)" "$(STATE_DIR)"
	$(FG_RUN) ./scripts/uvicorn_local.sh restart
	$(MAKE) -s fg-ready

fg-ready:
	@$(FG_RUN) ./scripts/uvicorn_local.sh check

fg-health:
	@curl -fsS "$(BASE_URL)/health" | $(PY) -m json.tool

fg-logs:
	@$(FG_RUN) ./scripts/uvicorn_local.sh logs $(or $(N),200)

fg-status:
	@set -euo pipefail; \
	echo "BASE_URL=$(BASE_URL)"; \
	echo "FG_ENV=$(FG_ENV)"; \
	echo "FG_AUTH_ENABLED=$(FG_AUTH_ENABLED)"; \
	echo "FG_ENFORCEMENT_MODE=$(FG_ENFORCEMENT_MODE)"; \
	echo "FG_STATE_DIR=$(FG_STATE_DIR)"; \
	echo "FG_SQLITE_PATH=$(FG_SQLITE_PATH)"; \
	test -f "$(FG_PIDFILE)" && echo "PID=$$(cat "$(FG_PIDFILE)")" || echo "PID=(none)"; \
	echo; \
	curl -fsS "$(BASE_URL)/health/live" 2>/dev/null || true; echo; \
	curl -fsS "$(BASE_URL)/health/ready" 2>/dev/null || true; echo

# =============================================================================
# OpenAPI reality checks (prevents Makefile lying)
# =============================================================================
.PHONY: fg-openapi-assert
fg-openapi-assert: fg-up
	@set -euo pipefail; \
	trap '$(MAKE) -s fg-down >/dev/null 2>&1 || true' EXIT; \
	command -v jq >/dev/null 2>&1 || (echo "❌ jq is required for fg-openapi-assert" && exit 1); \
	curl -fsS "$(BASE_URL)/openapi.json" | jq -e '.paths | has("/health") and has("/health/ready") and has("/feed/live") and (has("/defend") or has("/v1/defend")) and has("/decisions") and has("/stats")' >/dev/null; \
	echo "✅ OpenAPI core endpoints present"

# =============================================================================
# Snapshot
# =============================================================================
.PHONY: fg-snapshot fg-snapshot-all fg-boot
fg-snapshot:
	@bash ./scripts/snapshot_context.sh

fg-snapshot-all:
	@bash ./scripts/snapshot_all.sh

fg-boot: fg-fast itest-local fg-snapshot
	@echo "✅ Boot complete. Snapshot updated."

# =============================================================================
# UI / SSE helpers
# =============================================================================
.PHONY: fg-smoke-auth
fg-smoke-auth:
	@./scripts/smoke_auth.sh

# =============================================================================
# CI / Guards (opinionated)
# =============================================================================
.PHONY: ci-tools guard-no-hardcoded-8000 guard-no-pytest-detection guard-stream-markers build-sidecar ci

ci-tools:
	@command -v rg >/dev/null || (echo "❌ rg missing" && exit 1)
	@command -v curl >/dev/null || (echo "❌ curl missing" && exit 1)
	@command -v sqlite3 >/dev/null || (echo "❌ sqlite3 missing" && exit 1)
	@echo "✅ CI tools present"

guard-no-hardcoded-8000:
	@rg -n "127\.0\.0\.1:8000|:8000\b" api scripts/uvicorn_local.sh 2>/dev/null && \
	 (echo "❌ Hardcoded :8000 found in runtime code. Use HOST/PORT/BASE_URL." && exit 1) || \
	 echo "✅ No hardcoded :8000 in runtime code"

guard-no-pytest-detection:
	@rg -n "_running_under_pytest|PYTEST_CURRENT_TEST|sys\.modules\['pytest'\]" api/main.py >/dev/null && \
	 (echo "❌ Pytest-detection found in api/main.py. Remove test hacks." && exit 1) || \
	 echo "✅ No pytest-detection in api/main.py"

guard-stream-markers:
	@./scripts/guard_feed_stream_markers.sh

build-sidecar:
	@cd supervisor-sidecar && go build ./...

ci: ci-tools guard-no-hardcoded-8000 guard-no-pytest-detection guard-stream-markers fg-fast build-sidecar itest-local

# =============================================================================
# Integration tests (expects API running at BASE_URL)
# =============================================================================
.PHONY: test-integration
test-integration:
	@echo "== integration tests =="
	@test -n "$${BASE_URL:-}" || (echo "❌ BASE_URL is required" && exit 1)
	@test -n "$${FG_SQLITE_PATH:-}" || (echo "❌ FG_SQLITE_PATH is required (path to sqlite db)" && exit 1)
	@test -n "$${FG_API_KEY:-}" || (echo "❌ FG_API_KEY is required" && exit 1)
	@FG_BASE_URL="$${BASE_URL}" $(PY) -m pytest -q -m integration

# =============================================================================
# Integration test run (deterministic, no drift, no zombie reuse)
# =============================================================================

# ITest runtime (fixed + isolated)
ITEST_HOST     ?= 127.0.0.1
ITEST_PORT     ?= 8001
ITEST_BASE_URL ?= http://$(ITEST_HOST):$(ITEST_PORT)

# Dedicated itest DB (never the dev DB)
ITEST_DB       ?= $(CURDIR)/$(STATE_DIR)/frostgate-itest.db

# Optional: wipe DB each run (recommended)
ITEST_WIPE_DB  ?= 1

.PHONY: itest-local itest-down itest-up itest-db-reset

itest-db-reset:
	@set -euo pipefail; \
	mkdir -p "$(STATE_DIR)"; \
	if [ "$(ITEST_WIPE_DB)" = "1" ]; then \
	  rm -f "$(ITEST_DB)"; \
	fi; \
	FG_SQLITE_PATH="$(ITEST_DB)" $(PY) -c "from api.db import init_db; init_db()"; \
	echo "✅ itest db ready: $(ITEST_DB)"

# Stop only the itest instance (using same uvicorn_local.sh env contract)
itest-down:
	@set -euo pipefail; \
	$(MAKE) -s fg-down \
	  HOST="$(ITEST_HOST)" PORT="$(ITEST_PORT)" BASE_URL="$(ITEST_BASE_URL)" \
	  FG_SQLITE_PATH="$(ITEST_DB)" FG_API_KEY="$(FG_API_KEY)" FG_AUTH_ENABLED="$(FG_AUTH_ENABLED)" \
	  >/dev/null 2>&1 || true; \
	echo "✅ itest server stopped (or was not running)"

# Start only the itest instance (always clean lifecycle)
itest-up: itest-db-reset
	@set -euo pipefail; \
	$(MAKE) -s fg-up \
	  HOST="$(ITEST_HOST)" PORT="$(ITEST_PORT)" BASE_URL="$(ITEST_BASE_URL)" \
	  FG_SQLITE_PATH="$(ITEST_DB)" FG_API_KEY="$(FG_API_KEY)" FG_AUTH_ENABLED="$(FG_AUTH_ENABLED)"; \
	echo "✅ itest server up: $(ITEST_BASE_URL)"

# The deterministic integration run:
# - always stops first (no zombie port 8001)
# - always starts fresh with dedicated DB
# - always stops at the end (even on failure)
itest-local: itest-down itest-up
	@set -euo pipefail; \
	trap '$(MAKE) -s itest-down >/dev/null 2>&1 || true' EXIT; \
	\
	# smoke auth + integration suite against itest base
	BASE_URL="$(ITEST_BASE_URL)" FG_API_KEY="$(FG_API_KEY)" FG_SQLITE_PATH="$(ITEST_DB)" ./scripts/smoke_auth.sh; \
	BASE_URL="$(ITEST_BASE_URL)" FG_API_KEY="$(FG_API_KEY)" FG_SQLITE_PATH="$(ITEST_DB)" $(MAKE) -s test-integration; \
	echo "✅ itest-local OK"

# =============================================================================
# No drift: "new terminal sanity button"
# =============================================================================
.PHONY: no-drift no-drift-check-clean
no-drift: guard-stream-markers itest-local
	@$(PY) -m pytest -q
	@$(MAKE) -s no-drift-check-clean
	@echo "✅ no-drift OK"

no-drift-check-clean:
	@echo "== no-drift: git clean check =="; \
	st="$$(git status --porcelain)"; \
	if [ -n "$$st" ]; then \
		echo "❌ Working tree is dirty after no-drift run:"; \
		echo "$$st"; \
		exit 1; \
	fi

# =============================================================================
# Legacy aliases (keep docs/fingers intact)
# =============================================================================
.PHONY: up-local down-local restart-local logs-local ready-local health check test

.PHONY: test
test:
	python -m py_compile api/db.py tests/conftest.py backend/tests/conftest.py
	env -u FG_DB_URL -u FG_SQLITE_PATH -u FG_STATE_DIR -u FG_ENV pytest -q


up-local: fg-up
down-local: fg-down
restart-local: fg-restart
logs-local: fg-logs
ready-local: fg-ready
health: fg-health
check: fg-fast
test: fg-fast
.PHONY: test-clean
test-clean:
	python -m py_compile api/db.py api/auth_scopes.py tests/conftest.py backend/tests/conftest.py
	env -u FG_DB_URL -u FG_SQLITE_PATH -u FG_STATE_DIR -u FG_ENV pytest -q