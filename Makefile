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
PY_CONTRACT := $(if $(wildcard $(PY)),$(PY),python)
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
FG_API_KEY              ?=
FG_ENFORCEMENT_MODE     ?= observe
FG_DEV_EVENTS_ENABLED   ?= 0
FG_UI_TOKEN_GET_ENABLED ?= 1
ADMIN_SKIP_PIP_INSTALL  ?= 0

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
	"  make ci-pt" \
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

.PHONY: guard-scripts fg-audit-make fg-contract fg-compile contracts-gen

guard-scripts:
	@$(PY_CONTRACT) scripts/guard_no_paste_garbage.py
	@$(PY_CONTRACT) scripts/guard_makefile_sanity.py

fg-audit-make: guard-scripts
	@$(PY) scripts/audit_make_targets.py

contracts-gen:
	@PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=. $(PY_CONTRACT) scripts/contracts_gen.py

fg-contract: guard-scripts contracts-gen
	@$(PY_CONTRACT) scripts/contract_toolchain_check.py
	@$(PY_CONTRACT) scripts/contract_lint.py
	@git diff --exit-code contracts/admin
	@echo "Contract diff: OK"

fg-compile: guard-scripts
	@$(PY) -m py_compile api/main.py api/feed.py api/ui.py api/dev_events.py api/auth_scopes.py

# =============================================================================
# Production Profile Validation
# =============================================================================

.PHONY: prod-profile-check
prod-profile-check:
	@$(PY_CONTRACT) scripts/prod_profile_check.py

# =============================================================================
# Gap Audit (Production Readiness)
# =============================================================================

.PHONY: gap-audit release-gate generate-scorecard

gap-audit:
	@PYTHONPATH=scripts $(PY_CONTRACT) scripts/gap_audit.py

release-gate:
	@PYTHONPATH=scripts $(PY_CONTRACT) scripts/release_gate.py

generate-scorecard:
	@PYTHONPATH=scripts $(PY_CONTRACT) scripts/generate_scorecard.py

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
fg-fast: fg-audit-make fg-contract fg-compile prod-profile-check gap-audit
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
	@set -euo pipefail; \
	BASE_URL="$${BASE_URL:-$(ITEST_BASE_URL)}"; \
	FG_SQLITE_PATH="$${FG_SQLITE_PATH:-$(ITEST_DB)}"; \
	FG_API_KEY="$${FG_API_KEY:-$(FG_API_KEY)}"; \
	export BASE_URL FG_SQLITE_PATH FG_API_KEY; \
	\
	# Fast fail with a useful message if the API isn't up
	curl -fsS "$${BASE_URL}/health" >/dev/null || ( \
		echo "❌ API not reachable at BASE_URL=$${BASE_URL}"; \
		echo "   Start it with: make itest-up  (or run: make itest-local)"; \
		exit 1; \
	); \
	\
	rc=0; \
	FG_BASE_URL="$${BASE_URL}" $(PYTEST_ENV) $(PY) -m pytest -q -m integration || rc=$$?; \
	if [ $$rc -eq 5 ]; then \
		echo "⚠️  No integration tests collected (ok for now)"; \
		exit 0; \
	fi; \
	exit $$rc


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
	trap 'st=$$?; $(MAKE) -s itest-down >/dev/null 2>&1 || true; exit $$st' EXIT; \
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
	out="$(ARTIFACTS_DIR)/evidence_$${ts}_$(EVIDENCE_SCENARIO)"; \
	mkdir -p "$$out"; \
	git rev-parse HEAD > "$$out/git_head.txt"; \
	git status --porcelain=v1 > "$$out/git_status.txt" || true; \
	git log --oneline -20 > "$$out/git_log.txt" || true; \
	curl -fsS "$${BASE_URL}/health" > "$$out/health.json"; \
	curl -fsS "$${BASE_URL}/openapi.json" > "$$out/openapi.json"; \
	cp requirements.txt "$$out/requirements.txt" || true; \
	echo "$(EVIDENCE_SCENARIO)" > "$$out/scenario.txt"; \
	echo "$${ts}" > "$$out/timestamp.txt"; \
	( cd "$$out" && find . -type f -print0 | sort -z | xargs -0 sha256sum > manifest.sha256 ); \
	echo "$$out" > "$(ARTIFACTS_DIR)/latest_evidence_dir.txt"; \
	if [ -n "$${MINISIGN_SECRET_KEY:-}" ]; then \
	  echo "$${MINISIGN_SECRET_KEY}" > /tmp/minisign.key; \
	  minisign -Sm "$$out/manifest.sha256" -s /tmp/minisign.key -t "frostgate evidence $${ts}"; \
	  rm -f /tmp/minisign.key; \
	  echo "✅ signed manifest.sha256"; \
	else \
	  echo "⚠️  MINISIGN_SECRET_KEY not set, skipping signature"; \
	fi; \
	zipfile="$(ARTIFACTS_DIR)/frostgate_evidence_$${ts}_$(EVIDENCE_SCENARIO).zip"; \
	( cd "$(ARTIFACTS_DIR)" && zip -r "$$(basename $$zipfile)" "$$(basename $$out)" ); \
	echo "$$zipfile" > "$(ARTIFACTS_DIR)/latest_zip.txt"; \
	echo "✅ evidence bundle: $$zipfile"

ci-evidence: venv itest-down itest-up
	@set -euo pipefail; \
	trap 'st=$$?; $(MAKE) -s itest-down >/dev/null 2>&1 || true; exit $$st' EXIT; \
	BASE_URL="$(ITEST_BASE_URL)" FG_API_KEY="$(FG_API_KEY)" FG_SQLITE_PATH="$(ITEST_DB)" ./scripts/smoke_auth.sh; \
	BASE_URL="$(ITEST_BASE_URL)" FG_API_KEY="$(FG_API_KEY)" FG_SQLITE_PATH="$(ITEST_DB)" $(MAKE) -s test-integration; \
	SCENARIO="$${SCENARIO:-spike}" BASE_URL="$(ITEST_BASE_URL)" FG_API_KEY="$(FG_API_KEY)" \
	FG_SQLITE_PATH="$(ITEST_DB)" $(MAKE) -s evidence

# =============================================================================
# PT lane (security regression)
# =============================================================================

.PHONY: ci-pt
ci-pt: venv
	@$(PYTEST_ENV) $(PY) -m pytest -q tests/test_security_hardening.py tests/test_security_middleware.py

# =============================================================================

# =============================================================================
# Core Invariant Tests (INV-001 through INV-007)
# =============================================================================

.PHONY: test-core-invariants

test-core-invariants: venv
	@echo "Running core invariant tests (INV-001 through INV-007)."
	@$(PYTEST_ENV) $(PY) -m pytest -v tests/test_core_invariants.py

# Hardening Test Lanes (Day 1-7 hardening plan)
# =============================================================================

.PHONY: test-decision-unified test-tenant-isolation test-auth-hardening test-hardening-all

# Day 1: Unified decision pipeline
test-decision-unified: venv
	@$(PYTEST_ENV) $(PY) -m pytest -q tests/test_decision_pipeline_unified.py

# Day 2: Tenant isolation invariants
test-tenant-isolation: venv
	@$(PYTEST_ENV) $(PY) -m pytest -q tests/test_tenant_invariant.py tests/test_auth_tenants.py

# Day 3: Auth hardening and config fail-fast
test-auth-hardening: venv
	@$(PYTEST_ENV) $(PY) -m pytest -q tests/test_auth_hardening.py tests/test_auth.py tests/test_auth_contract.py

# All hardening tests
test-hardening-all: test-core-invariants test-decision-unified test-tenant-isolation test-auth-hardening
	@echo "✅ All hardening tests passed"

# CI lane for hardening (run on every PR)
.PHONY: ci-hardening
ci-hardening: venv test-hardening-all
	@echo "✅ Hardening CI gate passed"

# =============================================================================
# Admin Gateway
# =============================================================================

AG_HOST     ?= 127.0.0.1
AG_PORT     ?= 18001
AG_BASE_URL ?= http://$(AG_HOST):$(AG_PORT)
AG_VENV     ?= admin_gateway/.venv
ADMIN_PY    ?= python3
AG_PY       := $(AG_VENV)/bin/python
AG_PIP      := $(AG_VENV)/bin/pip

.PHONY: admin-venv admin-venv-check admin-dev admin-lint admin-test ci-admin

AG_REQS_STAMP := $(AG_VENV)/.requirements.sha256

admin-venv:
	set -euo pipefail; \
	echo "Admin venv: $(AG_VENV) (python: $$(command -v $(ADMIN_PY)))"; \
	command -v "$(ADMIN_PY)"; \
	"$(ADMIN_PY)" -V; \
	"$(ADMIN_PY)" -c "import sys; print(sys.executable)"; \
	"$(ADMIN_PY)" -m venv --upgrade "$(AG_VENV)"
	@# Skip pip install if explicitly disabled
	if [ "$${ADMIN_SKIP_PIP_INSTALL:-0}" = "1" ]; then \
		echo "Skipping admin-gateway package install (ADMIN_SKIP_PIP_INSTALL=1)"; \
		exit 0; \
	fi
	@# Compute requirements hash and compare with stamp file
	@set -euo pipefail; \
	REQS_HASH=$$(cat admin_gateway/requirements.txt admin_gateway/requirements-dev.txt 2>/dev/null | sha256sum | cut -d' ' -f1); \
	STAMP_HASH=$$(cat "$(AG_REQS_STAMP)" 2>/dev/null || echo "none"); \
	if [ "$$REQS_HASH" = "$$STAMP_HASH" ]; then \
		echo "Admin-gateway deps unchanged (stamp match), skipping pip install."; \
		if command -v ruff >/dev/null 2>&1 && [ ! -x "$(AG_VENV)/bin/ruff" ]; then \
			ln -sf "$$(command -v ruff)" "$(AG_VENV)/bin/ruff"; \
		fi; \
		exit 0; \
	fi; \
	if $(AG_PY) -c "import importlib.util; required=['fastapi','httpx','pytest','ruff']; missing=[name for name in required if importlib.util.find_spec(name) is None]; raise SystemExit(0 if not missing else 1)"; then \
		echo "Admin-gateway dependencies present in $(AG_VENV), updating stamp."; \
		echo "$$REQS_HASH" > "$(AG_REQS_STAMP)"; \
		if command -v ruff >/dev/null 2>&1 && [ ! -x "$(AG_VENV)/bin/ruff" ]; then \
			ln -sf "$$(command -v ruff)" "$(AG_VENV)/bin/ruff"; \
		fi; \
	else \
		echo "Installing admin-gateway dependencies into $(AG_VENV)."; \
		env -u HTTP_PROXY -u http_proxy -u HTTPS_PROXY -u https_proxy "$(AG_PIP)" install --upgrade pip; \
		env -u HTTP_PROXY -u http_proxy -u HTTPS_PROXY -u https_proxy "$(AG_PIP)" install -r admin_gateway/requirements.txt -r admin_gateway/requirements-dev.txt; \
		echo "$$REQS_HASH" > "$(AG_REQS_STAMP)"; \
	fi

.PHONY: admin-venv-check
admin-venv-check:
	@set -euo pipefail; \
	if [ -x "$(AG_PY)" ]; then \
		echo "Admin venv OK: $(AG_PY)"; \
		"$(AG_PY)" -V; \
		exit 0; \
	else \
		echo "Admin venv not ready: $(AG_PY) not found"; \
		exit 1; \
	fi

admin-dev: admin-venv
	@echo "Starting admin-gateway on $(AG_BASE_URL)..."
	@PYTHONPATH=. FG_ENV=dev $(AG_PY) -m uvicorn admin_gateway.main:app --host $(AG_HOST) --port $(AG_PORT) --reload

admin-lint: admin-venv
	@$(AG_PY) -m ruff check admin_gateway
	@$(AG_PY) -m ruff format --check admin_gateway

admin-test: admin-venv
	@PYTHONPATH=. $(PYTEST_ENV) $(AG_PY) -m pytest admin_gateway/tests -q

ci-admin: admin-venv admin-lint admin-test

# =============================================================================
# Compliance Gates
# =============================================================================

.PHONY: compliance-sbom compliance-provenance compliance-cis compliance-scap compliance-all

compliance-sbom:
	@mkdir -p "$(ARTIFACTS_DIR)"
	@$(PY) scripts/generate_sbom.py -o "$(ARTIFACTS_DIR)/sbom.json"

compliance-provenance:
	@mkdir -p "$(ARTIFACTS_DIR)"
	@$(PY) scripts/provenance.py -o "$(ARTIFACTS_DIR)/provenance.json"

compliance-cis:
	@mkdir -p "$(ARTIFACTS_DIR)"
	@$(PY) scripts/cis_check.py -o "$(ARTIFACTS_DIR)/cis_check.json" --fail-threshold 70

compliance-scap:
	@mkdir -p "$(ARTIFACTS_DIR)"
	@$(PY) scripts/scap_scan.py -o "$(ARTIFACTS_DIR)/scap_scan.json"

compliance-all: compliance-sbom compliance-provenance compliance-cis compliance-scap
	@echo "Compliance gates complete. Artifacts in $(ARTIFACTS_DIR)/"

# =============================================================================
# Console (Next.js)
# =============================================================================

CONSOLE_DIR := console

.PHONY: console-deps console-dev console-build console-lint console-test ci-console

console-deps:
	@cd $(CONSOLE_DIR) && npm ci --prefer-offline 2>/dev/null || npm install

console-dev: console-deps
	@echo "Starting console on http://localhost:3000..."
	@cd $(CONSOLE_DIR) && npm run dev

console-build: console-deps
	@cd $(CONSOLE_DIR) && npm run build

console-lint: console-deps
	@cd $(CONSOLE_DIR) && npm run lint

console-test: console-deps
	@cd $(CONSOLE_DIR) && npm run test

ci-console: console-lint console-test


guard-no-trash:
	@bad=$$(git ls-files | grep -E '^(agent_queue/|keys/|secrets/|state/|artifacts/|logs/|CONTEXT_SNAPSHOT\.md|supervisor-sidecar/supervisor-sidecar)' || true); \
	if [ -n "$$bad" ]; then \
	  echo "Forbidden tracked paths:"; echo "$$bad"; exit 1; \
	fi


.PHONY: deps-up deps-down

deps-up:
	@docker ps >/dev/null 2>&1 || (echo "Docker not running"; exit 1)
	@docker inspect fg-redis >/dev/null 2>&1 || \
	  docker run -d --name fg-redis -p 6379:6379 redis:7
	@echo "✅ deps up (redis on :6379)"

deps-down:
	@docker rm -f fg-redis >/dev/null 2>&1 || true
	@echo "✅ deps down"

.PHONY: fg-restart
fg-restart:
	@$(MAKE) -s fg-down || true
	@$(MAKE) -s fg-up


# =============================================================================
# Test Core Invariants
# =============================================================================

.PHONY: test-core-invariants
