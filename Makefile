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

# Ruff (format/lint)
RUFF ?= $(VENV)/bin/ruff

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

POSTGRES_USER     ?= fg_user
POSTGRES_DB       ?= frostgate
POSTGRES_PASSWORD ?= fg_password
POSTGRES_HOST     ?= 127.0.0.1
POSTGRES_PORT     ?= 5432
POSTGRES_URL      ?= postgresql+psycopg://$(POSTGRES_USER):$(POSTGRES_PASSWORD)@$(POSTGRES_HOST):$(POSTGRES_PORT)/$(POSTGRES_DB)

# Application role (non-superuser) for migrations, assertions, and tests.
# The bootstrap POSTGRES_USER cannot be demoted, so we use a separate role.
APP_DB_USER     ?= fg_app
APP_DB_PASSWORD ?= $(POSTGRES_PASSWORD)
APP_DB_URL      ?= postgresql+psycopg://$(APP_DB_USER):$(APP_DB_PASSWORD)@$(POSTGRES_HOST):$(POSTGRES_PORT)/$(POSTGRES_DB)

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
	"Formatting:" \
	"  make fmt        # auto-fix lint + format" \
	"  make fmt-check  # check-only (CI)" \
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
	"$(PIP)" install -c constraints.txt -r requirements.txt -r requirements-dev.txt

# =============================================================================
# Guards / audits
# =============================================================================

.PHONY: guard-scripts fg-audit-make fg-contract fg-compile contracts-gen contracts-core-gen contracts-core-diff artifact-contract-check contract-authority-check check-no-engine-evaluate opa-check verify-spine-modules verify-schemas verify-drift align-score

guard-scripts:
	@$(PY_CONTRACT) scripts/guard_no_paste_garbage.py
	@$(PY_CONTRACT) scripts/guard_makefile_sanity.py

check-no-engine-evaluate:
	@matches="$$(rg -n "from engine\\.evaluate import|import engine\\.evaluate|engine\\.evaluate\\(" api || true)"; \
	if [ -n "$$matches" ]; then \
		echo "$$matches"; \
		echo "Forbidden engine.evaluate usage found in api/."; \
		exit 1; \
	fi

opa-check:
	@if command -v opa >/dev/null 2>&1; then \
		opa check --strict policy/opa; \
		opa test policy/opa; \
	else \
		command -v docker >/dev/null 2>&1 || (echo "missing dependency: docker" && exit 1); \
		docker run --rm -v "$$PWD/policy/opa:/policies" openpolicyagent/opa:0.64.1 check --strict /policies; \
		docker run --rm -v "$$PWD/policy/opa:/policies" openpolicyagent/opa:0.64.1 test /policies; \
	fi

verify-spine-modules:
	@$(PY_CONTRACT) scripts/verify_spine_modules.py

verify-schemas:
	@$(PY_CONTRACT) scripts/verify_schemas.py

verify-drift:
	@$(PY_CONTRACT) scripts/verify_drift.py

align-score:
	@$(PY_CONTRACT) tools/align_score.py

fg-audit-make: guard-scripts
	@$(PY) scripts/audit_make_targets.py

contracts-gen:
	@PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=. $(PY_CONTRACT) scripts/contracts_gen.py
	@PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=. $(PY_CONTRACT) scripts/contracts_gen_core.py

contracts-core-gen:
	@PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=. $(PY_CONTRACT) scripts/contracts_gen_core.py

contracts-core-diff:
	@PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=. $(PY_CONTRACT) scripts/contracts_diff_core.py

artifact-contract-check:
	@PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=. $(PY_CONTRACT) scripts/artifact_schema_check.py

contract-authority-check:
	@PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=. $(PY_CONTRACT) scripts/contract_authority_check.py

fg-contract: guard-scripts contracts-gen
	@$(PY_CONTRACT) scripts/contract_toolchain_check.py
	@$(PY_CONTRACT) scripts/contract_lint.py
	@git diff --exit-code contracts/admin
	@$(PY_CONTRACT) scripts/contracts_diff_core.py
	@$(PY_CONTRACT) scripts/contract_authority_check.py
	@$(PY_CONTRACT) scripts/artifact_schema_check.py
	@echo "Contract diff: OK (admin/core/artifacts)"

fg-compile: guard-scripts
	@$(PY) -m py_compile api/main.py api/feed.py api/ui.py api/dev_events.py api/auth_scopes/__init__.py

# =============================================================================
# Production Profile Validation
# =============================================================================

.PHONY: prod-profile-check dos-hardening-check
prod-profile-check:
	@$(PY_CONTRACT) scripts/prod_profile_check.py

dos-hardening-check:
	@$(PYTEST_ENV) $(PY_CONTRACT) -m pytest -q -p no:unraisableexception tests/test_dos_guard.py
	@$(PY_CONTRACT) scripts/prod_profile_check.py

# =============================================================================
# Gap Audit (Production Readiness)
# =============================================================================

.PHONY: gap-audit release-gate generate-scorecard bp-c-001-gate bp-c-002-gate bp-c-003-gate bp-c-004-gate bp-d-000-gate

bp-c-001-gate:
	@$(PY_CONTRACT) scripts/verify_bp_c_001.py
	@echo "bp-c-001-gate: OK"

bp-c-002-gate:
	@$(PY_CONTRACT) scripts/verify_bp_c_002.py
	@echo "bp-c-002-gate: OK"

bp-c-003-gate:
	@$(PY_CONTRACT) scripts/verify_bp_c_003.py
	@echo "bp-c-003-gate: OK"

bp-c-004-gate:
	@$(PY_CONTRACT) scripts/verify_bp_c_004.py
	@echo "bp-c-004-gate: OK"

bp-d-000-gate:
	@$(PY_CONTRACT) scripts/verify_bp_d_000.py
	@echo "bp-d-000-gate: OK"

gap-audit:
	@PYTHONPATH=scripts $(PY_CONTRACT) scripts/gap_audit.py

release-gate:
	@PYTHONPATH=scripts $(PY_CONTRACT) scripts/release_gate.py

generate-scorecard:
	@PYTHONPATH=scripts $(PY_CONTRACT) scripts/generate_scorecard.py

# =============================================================================
# Formatting / Lint (ruff)
# =============================================================================

.PHONY: fmt fmt-check

# Auto-fix lint + apply formatting (local dev)
fmt:
	@$(RUFF) check --fix api tests scripts
	@$(RUFF) format api tests scripts
	@$(RUFF) check api tests scripts
	@$(RUFF) format --check api tests scripts

# Verify formatting + lint without modifying files (CI-safe)
fmt-check:
	@$(RUFF) check api tests scripts
	@$(RUFF) format --check api tests scripts

# =============================================================================
# Lint
# =============================================================================

.PHONY: fg-lint
fg-lint: fmt-check
	@$(PY) -m py_compile api/middleware/auth_gate.py

# =============================================================================
# Fast lane
# =============================================================================

.PHONY: fg-fast
fg-fast: fg-audit-make fg-contract fg-compile opa-check prod-profile-check dos-hardening-check gap-audit bp-c-001-gate bp-c-002-gate bp-c-003-gate bp-c-004-gate bp-d-000-gate verify-spine-modules verify-schemas verify-drift align-score
	@$(PYTEST_ENV) $(PY) -m pytest -q -m "not postgres"
	@$(MAKE) -s fg-lint

# =============================================================================
# Postgres verification (CI + local)
# =============================================================================

.PHONY: db-postgres-up db-postgres-migrate db-postgres-assert db-postgres-test db-postgres-verify db-postgres-down

db-postgres-up:
	@if [ ! -f .env ]; then \
		printf "POSTGRES_USER=%s\nPOSTGRES_DB=%s\nPOSTGRES_PASSWORD=%s\nREDIS_PASSWORD=%s\nFG_AGENT_API_KEY=%s\nAG_CORS_ORIGINS=%s\nNATS_AUTH_TOKEN=%s\nFG_API_KEY=%s\n" \
			"$(POSTGRES_USER)" "$(POSTGRES_DB)" "$(POSTGRES_PASSWORD)" "devredis" "dev-agent-key" "http://localhost:13000" "dev-nats-token" "dev-api-key" > .env; \
	fi
	@POSTGRES_USER="$(POSTGRES_USER)" POSTGRES_PASSWORD="$(POSTGRES_PASSWORD)" POSTGRES_DB="$(POSTGRES_DB)" \
		docker compose down -v --remove-orphans || true
	@POSTGRES_USER="$(POSTGRES_USER)" POSTGRES_PASSWORD="$(POSTGRES_PASSWORD)" POSTGRES_DB="$(POSTGRES_DB)" \
		docker compose up -d postgres
	@PGHOST="$(POSTGRES_HOST)" PGPORT="$(POSTGRES_PORT)" PGUSER="$(POSTGRES_USER)" PGDATABASE="$(POSTGRES_DB)" \
		./scripts/wait_for_postgres.sh
	@docker compose exec -T postgres psql -U "$(POSTGRES_USER)" -d "$(POSTGRES_DB)" -c "SELECT 1;" >/dev/null || { \
		echo "Postgres auth check failed."; \
		echo "POSTGRES_USER=$(POSTGRES_USER) POSTGRES_DB=$(POSTGRES_DB)"; \
		docker compose exec -T postgres sh -c 'env | grep "^POSTGRES_"' || true; \
		exit 1; \
	}
	@echo "Provisioning app role $(APP_DB_USER) (NOSUPERUSER NOBYPASSRLS)..."
	@docker compose exec -T postgres psql -v ON_ERROR_STOP=1 -U "$(POSTGRES_USER)" -d "$(POSTGRES_DB)" -c "\
		DO \$$\$$ BEGIN \
		  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = '$(APP_DB_USER)') THEN \
		    CREATE ROLE $(APP_DB_USER) WITH LOGIN PASSWORD '$(APP_DB_PASSWORD)' \
		      NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB; \
		  END IF; \
		END \$$\$$; \
		ALTER DATABASE $(POSTGRES_DB) OWNER TO $(APP_DB_USER); \
		GRANT ALL ON SCHEMA public TO $(APP_DB_USER);"
	@docker compose exec -T postgres psql -U "$(APP_DB_USER)" -d "$(POSTGRES_DB)" \
		-c "SELECT rolname, rolsuper, rolbypassrls FROM pg_roles WHERE rolname = current_user;"

db-postgres-migrate:
	@FG_DB_URL="$(APP_DB_URL)" FG_DB_BACKEND="postgres" $(PY) -m api.db_migrations --backend postgres --apply

db-postgres-assert:
	@FG_DB_URL="$(APP_DB_URL)" FG_DB_BACKEND="postgres" $(PY) -m api.db_migrations --backend postgres --assert

db-postgres-test:
	@FG_DB_URL="$(APP_DB_URL)" FG_DB_BACKEND="postgres" $(PYTEST_ENV) $(PY) -m pytest -q tests/postgres

db-postgres-verify: db-postgres-up db-postgres-migrate db-postgres-assert db-postgres-test

db-postgres-down:
	@docker compose stop postgres || true

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

.PHONY: ci ci-integration ci-evidence pip-audit

ci: venv pip-audit fg-fast

ci-integration: venv itest-local

pip-audit: venv
	"$(PIP)" install --upgrade pip-audit
	"$(PY)" -m pip_audit -r requirements.txt -r requirements-dev.txt
	"$(PY)" -m pip_audit -r admin_gateway/requirements.txt -r admin_gateway/requirements-dev.txt

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
# Core Invariant Tests (INV-001 through INV-007)
# =============================================================================

.PHONY: test-core-invariants

test-core-invariants: venv
	@echo "Running core invariant tests (INV-001 through INV-007)."
	@$(PYTEST_ENV) $(PY) -m pytest -v tests/test_core_invariants.py tests/test_ui_dashboards.py

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
	@$(PYTEST_ENV) $(PY) -m pytest -q tests/test_auth_hardening.py tests/test_auth.py tests/test_auth_contract.py tests/security/test_evidence_chain_persistence.py tests/security/test_chain_verification_detects_tamper.py tests/security/test_scope_enforcement.py tests/security/test_key_hashing_kdf.py

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
AG_PIP_INDEX_URL ?=
AG_PIP_FIND_LINKS ?=
AG_PIP_NO_INDEX ?=

AG_PIP_ENV :=
ifneq ($(strip $(AG_PIP_INDEX_URL)),)
AG_PIP_ENV += PIP_INDEX_URL=$(AG_PIP_INDEX_URL)
endif
ifneq ($(strip $(AG_PIP_FIND_LINKS)),)
AG_PIP_ENV += PIP_FIND_LINKS=$(AG_PIP_FIND_LINKS)
endif
ifneq ($(strip $(AG_PIP_NO_INDEX)),)
AG_PIP_ENV += PIP_NO_INDEX=$(AG_PIP_NO_INDEX)
endif

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
		env -u HTTP_PROXY -u http_proxy -u HTTPS_PROXY -u https_proxy $(AG_PIP_ENV) "$(AG_PIP)" install --upgrade pip; \
		env -u HTTP_PROXY -u http_proxy -u HTTPS_PROXY -u https_proxy $(AG_PIP_ENV) "$(AG_PIP)" install -c constraints.txt -r admin_gateway/requirements.txt -r admin_gateway/requirements-dev.txt; \
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

# =============================================================================
# PR Parity Checks (run locally what PR runs)
# =============================================================================

.PHONY: pr-check pr-check-all pr-check-ci pr-check-verify-targets
.PHONY: paste-garbage guard makefile-sanity
.PHONY: pr-check-fast pr-check-lint pr-check-test pr-check-contract pr-check-prod

__mkdb__:

paste-garbage:
	@$(MAKE) -s guard-no-trash
	@echo "paste-garbage guard: OK"

guard:
	@$(MAKE) -s guard-scripts
	@$(MAKE) -s guard-no-trash
	@echo "guard: OK"

makefile-sanity:
	@$(MAKE) -s guard-scripts
	@echo "Makefile sanity: OK"

pr-check-fast:
	@$(MAKE) -s fg-fast
	@echo "pr-check-fast: OK"

pr-check-lint:
	@$(MAKE) -s fg-lint
	@echo "pr-check-lint: OK"

pr-check-test:
	@test -x "$(PY)" || (echo "❌ venv missing. Run: make venv"; exit 1)
	@$(PYTEST_ENV) $(PY) -m pytest -q -m "not postgres"
	@echo "pr-check-test: OK"

pr-check-contract:
	@$(MAKE) -s fg-contract
	@echo "pr-check-contract: OK"

pr-check-prod:
	@$(MAKE) -s opa-check prod-profile-check dos-hardening-check gap-audit
	@echo "pr-check-prod: OK"

PR_CHECK_REQUIRED_TARGETS := \
	paste-garbage guard makefile-sanity \
	pr-check-fast pr-check-lint pr-check-test pr-check-contract pr-check-prod

pr-check-verify-targets:
	@set -euo pipefail; \
	tmp="$$(mktemp)"; trap 'rm -f "$$tmp"' EXIT; \
	$(MAKE) -qpRr __mkdb__ > "$$tmp" 2>/dev/null; \
	missing=0; dup=0; \
	for t in $(PR_CHECK_REQUIRED_TARGETS); do \
		cnt="$$(grep -cE "^$${t}:[[:space:]]*($$|[^=])" "$$tmp" || true)"; \
		if [ "$$cnt" -eq 0 ]; then echo "❌ Missing make target: $$t"; missing=1; \
		elif [ "$$cnt" -gt 1 ]; then echo "❌ Duplicate make target definition: $$t ($$cnt)"; dup=1; fi; \
	done; \
	test $$missing -eq 0; test $$dup -eq 0; \
	echo "✅ pr-check prerequisites present"

# Minimal parity: cheap repo guard + fg-fast once
pr-check: pr-check-verify-targets
	@$(MAKE) -s paste-garbage
	@$(MAKE) -s pr-check-fast
	@echo "✅ pr-check: PASS"

pr-check-all: pr-check
	@$(MAKE) -s release-gate
	@echo "✅ pr-check-all (includes release-gate): PASS"

pr-check-ci: pr-check-all
	@echo "✅ pr-check-ci: PASS"

