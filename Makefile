# =============================================================================
# FrostGate Core - Makefile (single source of truth)
# Production grade: deterministic venv + CI/Codex stability + fail-closed guards
# =============================================================================

SHELL := /bin/bash
.ONESHELL:
.SHELLFLAGS := -euo pipefail -c
.DELETE_ON_ERROR:
.DEFAULT_GOAL := help

MAKEFLAGS += --no-print-directory

# =============================================================================
# Repo + Python
# =============================================================================

VENV_DIR ?= .venv
VENV := $(VENV_DIR)
PY  := $(VENV)/bin/python
PIP := $(VENV)/bin/pip
RUFF := $(VENV)/bin/ruff
PYTEST := $(VENV)/bin/pytest

DEPS_STAMP := $(VENV_DIR)/.deps.stamp
DEPS_INPUTS := requirements.txt requirements-dev.txt constraints.txt

export PYTHONPATH := .
export PIP_DISABLE_PIP_VERSION_CHECK := 1
export PIP_NO_PYTHON_VERSION_WARNING := 1

# Prefer venv for contract scripts too (Codex determinism).
PY_CONTRACT := $(PY)

PYTEST_ENV := env PYTHONHASHSEED=0 TZ=UTC

# =============================================================================
# Setup (deterministic + fast via deps stamp)
# =============================================================================

.PHONY: venv venv-force

venv: $(DEPS_STAMP)
	@echo "✅ venv ready: $(PY)"

venv-force:
	@rm -f "$(DEPS_STAMP)"
	@$(MAKE) venv

$(DEPS_STAMP): $(DEPS_INPUTS)
	@set -euo pipefail; \
	test -d "$(VENV)" || python -m venv "$(VENV)"; \
	hash="$$(sha256sum $(DEPS_INPUTS) | sha256sum | awk '{print $$1}')"; \
	prev="$$(cat "$(DEPS_STAMP)" 2>/dev/null || echo "")"; \
	if [ "$$hash" = "$$prev" ] && [ -n "$$prev" ]; then \
		echo "✅ deps unchanged (stamp match)"; \
		exit 0; \
	fi; \
	echo "==> deps changed: installing"; \
	"$(PIP)" install --upgrade pip wheel >/dev/null; \
	"$(PIP)" install -c constraints.txt -r requirements.txt -r requirements-dev.txt; \
	echo "$$hash" > "$(DEPS_STAMP)"

# =============================================================================
# Tooling capability probes (Codex/CI may not have these CLIs)
# =============================================================================

HAS_DOCKER := $(shell command -v docker >/dev/null 2>&1 && echo 1 || echo 0)
HAS_HELM   := $(shell command -v helm  >/dev/null 2>&1 && echo 1 || echo 0)

.PHONY: tools-check require-docker require-helm require-opa-runtime tools

tools-check:
	@echo "docker: $(if $(filter 1,$(HAS_DOCKER)),yes,no)"
	@echo "helm:  $(if $(filter 1,$(HAS_HELM)),yes,no)"

require-docker:
	@test "$(HAS_DOCKER)" = "1" || (echo "❌ docker CLI missing" && exit 1)

require-helm:
	@test "$(HAS_HELM)" = "1" || (echo "❌ helm CLI missing" && exit 1)

# =============================================================================
# Tooling versions (single source of truth)
# =============================================================================

OPA_IMAGE ?= openpolicyagent/opa:0.64.1@sha256:34402172b65ceddd52461f227f998b2048c09a62cb4ba253cb0cc0504ea608de

require-opa-runtime:
	@set -euo pipefail; \
	if command -v opa >/dev/null 2>&1; then \
		echo "✅ opa-check runtime: local opa CLI"; \
		exit 0; \
	fi; \
	if command -v docker >/dev/null 2>&1; then \
		echo "✅ opa-check runtime: dockerized opa ($(OPA_IMAGE))"; \
		exit 0; \
	fi; \
	echo "❌ missing dependency: install 'opa' CLI or 'docker' to run opa-check"; \
	exit 1

# =============================================================================
# Runtime defaults
# =============================================================================

HOST     ?= 127.0.0.1
PORT     ?= 8000
BASE_URL ?= http://$(HOST):$(PORT)

# We intentionally override per lane:
# - Contracts + prod profile checks: FG_ENV=prod
# - Unit tests: FG_ENV=test
FG_ENV                  ?= dev

FG_SERVICE              ?= frostgate-core
FG_AUTH_ENABLED         ?= 1
FG_API_KEY              ?=
FG_ENFORCEMENT_MODE     ?= observe
FG_DEV_EVENTS_ENABLED   ?= 0
FG_UI_TOKEN_GET_ENABLED ?= 1
ADMIN_SKIP_PIP_INSTALL  ?= 0

# Admin-gateway dev-bypass tenant defaults (tests expect tenant-dev)
FG_DEV_TENANT_ID        ?= tenant-dev
FG_DEV_ALLOWED_TENANTS  ?= tenant-dev


ARTIFACTS_DIR ?= artifacts
STATE_DIR     ?= state

# NOTE: FG_STATE_DIR should be state, not artifacts.
FG_STATE_DIR   ?= $(CURDIR)/$(STATE_DIR)
FG_SQLITE_PATH ?= $(FG_STATE_DIR)/frostgate.db

POSTGRES_USER     ?= fg_user
POSTGRES_DB       ?= frostgate
POSTGRES_PASSWORD ?= fg_password
POSTGRES_HOST     ?= 127.0.0.1
POSTGRES_PORT     ?= 5432
POSTGRES_URL      ?= postgresql+psycopg://$(POSTGRES_USER):$(POSTGRES_PASSWORD)@$(POSTGRES_HOST):$(POSTGRES_PORT)/$(POSTGRES_DB)

APP_DB_USER     ?= fg_app
APP_DB_PASSWORD ?= $(POSTGRES_PASSWORD)

APP_DB_URL_HOST    ?= postgresql+psycopg://$(APP_DB_USER):$(APP_DB_PASSWORD)@127.0.0.1:$(POSTGRES_PORT)/$(POSTGRES_DB)
APP_DB_URL_COMPOSE ?= postgresql+psycopg://$(APP_DB_USER):$(APP_DB_PASSWORD)@postgres:5432/$(POSTGRES_DB)

APP_DB_URL ?= $(APP_DB_URL_HOST)

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
# Internal helpers (no footguns)
# =============================================================================

.PHONY: _require-venv _require-pytest-venv _print-tools

_require-venv:
	@test -x "$(PY)" || (echo "❌ venv missing at $(PY). Run: make venv" && exit 1)

_require-pytest-venv:
	@test -x "$(PYTEST)" || (echo "❌ pytest missing in venv: run make venv" && exit 2)

_print-tools:
	@echo "Tooling snapshot:"; \
	echo "  python: $$(command -v python || true)"; \
	echo "  venv python: $(PY)"; \
	test -x "$(PY)" && "$(PY)" -V || true; \
	test -x "$(PIP)" && "$(PIP)" -V || true; \
	test -x "$(RUFF)" && "$(RUFF)" --version || true; \
	command -v docker >/dev/null 2>&1 && docker --version || echo "  docker: (missing)"; \
	command -v helm  >/dev/null 2>&1 && helm version --short || echo "  helm: (missing)"; \
	command -v opa   >/dev/null 2>&1 && opa version || echo "  opa: (missing)"

tools: _print-tools

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
	"" \
	"Diagnostics:" \
	"  make tools      # print versions + missing CLIs"

# =============================================================================
# Convenience
# =============================================================================

.PHONY: fix ci-local
fix: venv
	@$(RUFF) check . --fix
	@$(RUFF) format .

ci-local: fix fg-fast

# =============================================================================
# Guards / audits
# =============================================================================

.PHONY: guard-scripts fg-audit-make fg-contract fg-compile \
	contracts-gen contracts-core-gen contracts-core-diff \
	artifact-contract-check contract-authority-check contract-authority-refresh \
	check-no-engine-evaluate opa-check verify-spine-modules verify-schemas verify-drift align-score \
	contracts-gen-prod fg-contract-prod test-unit

guard-scripts: venv
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
	@set -euo pipefail; \
	POLICY_DIR="$$PWD/policy/opa"; \
	$(MAKE) -s require-opa-runtime; \
	if command -v opa >/dev/null 2>&1; then \
		echo "opa-check: using local opa CLI"; \
		opa check --strict "$$POLICY_DIR"; \
		opa test "$$POLICY_DIR"; \
	else \
		IMAGE="$(OPA_IMAGE)"; \
		MOUNT="-v $$POLICY_DIR:/policies"; \
		echo "opa-check: using pinned docker image $$IMAGE"; \
		docker run --rm $$MOUNT "$$IMAGE" check --strict /policies; \
		docker run --rm $$MOUNT "$$IMAGE" test /policies; \
	fi

verify-spine-modules: venv
	@$(PY_CONTRACT) scripts/verify_spine_modules.py

verify-schemas: venv
	@$(PY_CONTRACT) scripts/verify_schemas.py

verify-drift: venv
	@$(PY_CONTRACT) scripts/verify_drift.py

align-score: venv
	@$(PY_CONTRACT) tools/align_score.py

fg-audit-make: guard-scripts
	@$(PY) scripts/audit_make_targets.py

# =============================================================================
# Contracts
# =============================================================================

contracts-gen: venv
	@PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=. $(PY_CONTRACT) scripts/contracts_gen.py
	@PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=. $(PY_CONTRACT) scripts/contracts_gen_core.py

contracts-gen-prod: venv
	@FG_ENV=prod $(MAKE) -s contracts-gen

contracts-core-gen: venv
	@PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=. $(PY_CONTRACT) scripts/contracts_gen_core.py

contracts-core-diff: venv
	@PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=. $(PY_CONTRACT) scripts/contracts_diff_core.py

artifact-contract-check: venv
	@PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=. $(PY_CONTRACT) scripts/artifact_schema_check.py

contract-authority-check: venv
	@PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=. $(PY_CONTRACT) scripts/contract_authority_check.py

contract-authority-refresh: venv
	@FG_ENV=prod $(MAKE) -s contracts-gen
	@PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=. $(PY_CONTRACT) scripts/refresh_contract_authority.py

fg-contract: venv guard-scripts
	@FG_ENV=prod $(MAKE) -s contracts-gen
	@$(PY_CONTRACT) scripts/contract_toolchain_check.py
	@$(PY_CONTRACT) scripts/contract_lint.py
	@git diff --exit-code contracts/admin
	@$(PY_CONTRACT) scripts/contracts_diff_core.py
	@$(PY_CONTRACT) scripts/contract_authority_check.py
	@$(PY_CONTRACT) scripts/artifact_schema_check.py
	@echo "Contract diff: OK (admin/core/artifacts)"

fg-contract-prod: venv guard-scripts
	@FG_ENV=prod $(MAKE) -s fg-contract

fg-compile: _require-venv guard-scripts
	@$(PY) -m py_compile api/main.py api/feed.py api/ui.py api/dev_events.py api/auth_scopes/__init__.py

# =============================================================================
# Production Profile Validation
# =============================================================================

.PHONY: prod-profile-check dos-hardening-check
prod-profile-check: venv
	@FG_ENV=prod $(PY_CONTRACT) scripts/prod_profile_check.py

dos-hardening-check: _require-venv
	@FG_ENV=prod $(PYTEST_ENV) $(PYTEST) -q -p no:unraisableexception tests/test_dos_guard.py
	@FG_ENV=prod $(PY_CONTRACT) scripts/prod_profile_check.py

# =============================================================================
# Gap Audit (Production Readiness)
# =============================================================================

.PHONY: gap-audit release-gate generate-scorecard \
	prod-unsafe-config-check security-regression-gates soc-invariants enforcement-mode-matrix \
	route-inventory-audit route-inventory-generate test-quality-gate soc-review-sync pr-base-mainline-check \
	rebase-main-instructions audit-chain-verify compliance-chain-verify canonicalization-guard \
	bp-s0-001-gate bp-s0-005-gate bp-c-001-gate bp-c-002-gate bp-c-003-gate bp-c-004-gate bp-c-005-gate bp-c-006-gate \
	bp-m1-006-gate bp-m2-001-gate bp-m2-002-gate bp-m2-003-gate \
	bp-m3-001-gate bp-m3-003-gate bp-m3-004-gate bp-m3-005-gate bp-m3-006-gate bp-m3-007-gate bp-d-000-gate

# Blueprint gates
bp-s0-001-gate: venv
	@$(PY_CONTRACT) scripts/verify_bp_s0_001.py
	@echo "bp-s0-001-gate: OK"

bp-s0-005-gate: venv
	@$(PY_CONTRACT) scripts/verify_bp_s0_005.py
	@echo "bp-s0-005-gate: OK"

bp-c-001-gate: venv
	@$(PY_CONTRACT) scripts/verify_bp_c_001.py
	@echo "bp-c-001-gate: OK"

bp-c-002-gate: venv
	@$(PY_CONTRACT) scripts/verify_bp_c_002.py
	@echo "bp-c-002-gate: OK"

bp-c-003-gate: venv
	@$(PY_CONTRACT) scripts/verify_bp_c_003.py
	@echo "bp-c-003-gate: OK"

bp-c-004-gate: venv
	@$(PY_CONTRACT) scripts/verify_bp_c_004.py
	@echo "bp-c-004-gate: OK"

bp-c-005-gate: venv
	@$(PY_CONTRACT) scripts/verify_bp_c_005.py
	@echo "bp-c-005-gate: OK"

bp-c-006-gate: venv
	@$(PY_CONTRACT) scripts/verify_bp_c_006.py
	@echo "bp-c-006-gate: OK"

bp-m1-006-gate: venv
	@$(PY_CONTRACT) scripts/verify_bp_m1_006.py
	@echo "bp-m1-006-gate: OK"

bp-m2-001-gate: venv
	@$(PY_CONTRACT) scripts/verify_bp_m2_001.py
	@echo "bp-m2-001-gate: OK"

bp-m2-002-gate: venv
	@$(PY_CONTRACT) scripts/verify_bp_m2_002.py
	@echo "bp-m2-002-gate: OK"

bp-m2-003-gate: venv
	@$(PY_CONTRACT) scripts/verify_bp_m2_003.py
	@echo "bp-m2-003-gate: OK"

bp-m3-001-gate: venv
	@$(PY_CONTRACT) scripts/verify_bp_m3_001.py
	@echo "bp-m3-001-gate: OK"

bp-m3-003-gate: venv
	@$(PY_CONTRACT) scripts/verify_bp_m3_003.py
	@echo "bp-m3-003-gate: OK"

bp-m3-004-gate: venv
	@$(PY_CONTRACT) scripts/verify_bp_m3_004.py
	@echo "bp-m3-004-gate: OK"

bp-m3-005-gate: venv
	@$(PY_CONTRACT) scripts/verify_bp_m3_005.py
	@echo "bp-m3-005-gate: OK"

bp-m3-006-gate: venv
	@$(PY_CONTRACT) scripts/verify_bp_m3_006.py
	@echo "bp-m3-006-gate: OK"

bp-m3-007-gate: venv
	@$(PY_CONTRACT) scripts/verify_bp_m3_007.py
	@echo "bp-m3-007-gate: OK"

bp-d-000-gate: venv
	@$(PY_CONTRACT) scripts/verify_bp_d_000.py
	@echo "bp-d-000-gate: OK"

prod-unsafe-config-check: venv
	@$(PY) tools/ci/check_prod_unsafe_config.py

security-regression-gates: venv
	@$(PY) tools/ci/check_security_regression_gates.py
	@$(PY) tools/ci/check_openapi_security_diff.py
	@$(PY) tools/ci/check_artifact_policy.py

soc-invariants: venv
	@PYTHONPATH=. $(PY) tools/ci/check_soc_invariants.py

enforcement-mode-matrix: venv
	@$(PY) tools/ci/check_enforcement_mode_matrix.py

route-inventory-generate: venv
	@$(PY) tools/ci/check_route_inventory.py --write

route-inventory-audit: venv
	@PYTHONPATH=. $(PY) tools/ci/check_route_inventory.py

test-quality-gate: venv
	@$(PY) tools/ci/check_test_quality.py

soc-review-sync: venv
	@$(PY) tools/ci/check_soc_review_sync.py

pr-base-mainline-check: venv
	@$(PY) tools/ci/check_pr_base_is_mainline.py

rebase-main-instructions:
	@printf "%s\n" \
	"Rebase workflow (run in your local clone):" \
	"  git remote -v" \
	"  git fetch origin" \
	"  git rebase origin/main" \
	"  git push --force-with-lease" \
	"" \
	"Verify SOC review doc is not re-added after rebase:" \
	"  git diff --name-status origin/main...HEAD | rg '^A[[:space:]]+docs/SOC_ARCH_REVIEW_2026-02-15.md$$' && echo '❌ still added' && exit 1 || echo '✅ not added as new'"

audit-chain-verify: venv
	@$(PY) scripts/verify_audit_chain.py

compliance-chain-verify: venv
	@$(PY) scripts/verify_compliance_chain.py

canonicalization-guard: venv
	@$(PY) scripts/verify_canonicalization_guard.py

gap-audit: venv
	@FG_ENV=prod PYTHONPATH=scripts $(PY_CONTRACT) scripts/gap_audit.py

release-gate: venv
	@FG_ENV=prod PYTHONPATH=scripts $(PY_CONTRACT) scripts/release_gate.py

generate-scorecard: venv
	@FG_ENV=prod PYTHONPATH=scripts $(PY_CONTRACT) scripts/generate_scorecard.py

# =============================================================================
# Formatting / Lint (ruff) - venv always
# =============================================================================

.PHONY: fmt fmt-check fg-lint

fmt: _require-venv
	@$(RUFF) check --fix api tests scripts
	@$(RUFF) format api tests scripts
	@$(RUFF) check api tests scripts
	@$(RUFF) format --check api tests scripts

fmt-check: _require-venv
	@$(RUFF) check api tests scripts
	@$(RUFF) format --check api tests scripts

fg-lint: fmt-check
	@$(PY) -m py_compile api/middleware/auth_gate.py

# =============================================================================
# Unit tests lane (ALWAYS run as FG_ENV=test)
# =============================================================================

.PHONY: test-unit
test-unit: venv _require-pytest-venv
	@FG_ENV=test $(PYTEST_ENV) $(PYTEST) -q -m "not postgres"

# =============================================================================
# Fast lane + audit/compliance
# =============================================================================

.PHONY: audit-engine audit-export-test audit-repro-test compliance-registry-test exam-export-test exam-reproduce-test
audit-engine: venv
	@$(PY) scripts/run_audit_engine.py

audit-export-test: venv _require-pytest-venv
	@FG_ENV=test $(PYTEST_ENV) $(PYTEST) -q tests/test_audit_engine.py -k "deterministic_export"

audit-repro-test: venv _require-pytest-venv
	@FG_ENV=test $(PYTEST_ENV) $(PYTEST) -q tests/test_audit_engine.py -k "reproducibility_mismatch"

compliance-registry-test: venv _require-pytest-venv
	@FG_ENV=test $(PYTEST_ENV) $(PYTEST) -q tests/test_compliance_registry.py

exam-export-test: venv _require-pytest-venv
	@FG_ENV=test $(PYTEST_ENV) $(PYTEST) -q tests/test_audit_engine.py -k "exam_export"

exam-reproduce-test: venv _require-pytest-venv
	@FG_ENV=test $(PYTEST_ENV) $(PYTEST) -q tests/test_audit_engine.py -k "exam_reproduce"

.PHONY: fg-fast fg-fast-ci fg-fast-full

fg-fast: venv fg-audit-make fg-contract fg-compile prod-profile-check \
	prod-unsafe-config-check security-regression-gates soc-invariants soc-manifest-verify \
	route-inventory-audit test-quality-gate soc-review-sync pr-base-mainline-check \
	audit-chain-verify dos-hardening-check sql-migration-percent-guard gap-audit \
	bp-s0-001-gate bp-s0-005-gate bp-c-001-gate bp-c-002-gate bp-c-003-gate bp-c-004-gate bp-c-005-gate bp-c-006-gate \
	bp-m1-006-gate bp-m2-001-gate bp-m2-002-gate bp-m2-003-gate \
	bp-m3-001-gate bp-m3-003-gate bp-m3-004-gate bp-m3-005-gate bp-m3-006-gate bp-m3-007-gate bp-d-000-gate \
	verify-spine-modules verify-schemas verify-drift align-score
	@$(MAKE) -s test-unit
	@$(MAKE) -s fg-lint
	@$(MAKE) -s test-dashboard-p0
	@$(MAKE) -s sql-migration-percent-guard

fg-fast-ci: fg-fast billing-ledger-verify billing-invoice-verify opa-check

fg-fast-full: fg-fast-ci audit-chain-verify compliance-chain-verify canonicalization-guard \
	audit-export-test audit-repro-test compliance-registry-test exam-export-test exam-reproduce-test

# =============================================================================
# Billing
# =============================================================================

.PHONY: billing-ledger-verify billing-invoice-verify billing-daily-sync billing-evidence-verify

billing-ledger-verify: venv _require-pytest-venv
	@FG_ENV=test $(PYTEST_ENV) $(PYTEST) -q tests/test_billing_module.py -k "identity_dedupe_priority or identity_conflict_quarantine_and_resolution_events or device_enrollment_and_activity_proof or tenant_isolation_adversarial_reads_and_writes or scope_bypass_denied"

billing-invoice-verify: venv _require-pytest-venv
	@FG_ENV=test $(PYTEST_ENV) $(PYTEST) -q tests/test_billing_module.py -k "invoice_determinism_and_reproduce or reproduce_mismatch_detection or evidence_export_contains_manifest_and_attestation or billing_run_model or invoice_finalize_freezes_evidence or coverage_day_contract_metadata or credit_note_append_only_flow"

billing-daily-sync: venv _require-pytest-venv
	@FG_ENV=test $(PYTEST_ENV) $(PYTEST) -q tests/test_billing_module.py -k "daily_count_sync_incremental_has_tamper_evident_checkpoint"

billing-evidence-verify: venv
	@test -n "$(BUNDLE_DIR)" || (echo "BUNDLE_DIR is required" && exit 1)
	@$(PY) scripts/fg_billing_verify.py "$(BUNDLE_DIR)" --pubkey "$(BUNDLE_DIR)/attestation.pub"

# =============================================================================
# Postgres verification (CI + local)
# =============================================================================

.PHONY: db-postgres-up db-postgres-migrate db-postgres-assert db-postgres-test db-postgres-verify db-postgres-down

db-postgres-up:
	@$(MAKE) -s require-docker
	@if [ ! -f .env ]; then \
		printf "POSTGRES_USER=%s\nPOSTGRES_DB=%s\nPOSTGRES_PASSWORD=%s\nREDIS_PASSWORD=%s\nFG_AGENT_API_KEY=%s\nAG_CORS_ORIGINS=%s\nNATS_AUTH_TOKEN=%s\nFG_API_KEY=%s\nFG_WEBHOOK_SECRET=%s\n" \
			"$(POSTGRES_USER)" "$(POSTGRES_DB)" "$(POSTGRES_PASSWORD)" "devredis" "dev-agent-key" "http://localhost:13000" "dev-nats-token" "dev-api-key" "dev-webhook-secret" > .env; \
	fi
	@POSTGRES_USER="$(POSTGRES_USER)" POSTGRES_PASSWORD="$(POSTGRES_PASSWORD)" POSTGRES_DB="$(POSTGRES_DB)" \
		docker compose down -v --remove-orphans || true
	@POSTGRES_USER="$(POSTGRES_USER)" POSTGRES_PASSWORD="$(POSTGRES_PASSWORD)" POSTGRES_DB="$(POSTGRES_DB)" \
		docker compose up -d postgres
	@PGHOST="$(POSTGRES_HOST)" PGPORT="$(POSTGRES_PORT)" PGUSER="$(POSTGRES_USER)" PGDATABASE="$(POSTGRES_DB)" \
		./scripts/wait_for_postgres.sh
	@docker compose exec -T postgres psql -v ON_ERROR_STOP=1 -U "$(POSTGRES_USER)" -d "$(POSTGRES_DB)" <<-'SQL'
	DO $$$$
	BEGIN
	  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = '$(APP_DB_USER)') THEN
	    CREATE ROLE $(APP_DB_USER) WITH LOGIN PASSWORD '$(APP_DB_PASSWORD)'
	      NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB;
	  END IF;

	  /* Force password every run so auth never drifts. */
	  ALTER ROLE $(APP_DB_USER) WITH PASSWORD '$(APP_DB_PASSWORD)';
	END
	$$$$;

	ALTER DATABASE $(POSTGRES_DB) OWNER TO $(APP_DB_USER);
	GRANT ALL ON SCHEMA public TO $(APP_DB_USER);
	SQL
	@docker compose exec -T postgres psql -U "$(APP_DB_USER)" -d "$(POSTGRES_DB)" \
		-c "SELECT rolname, rolsuper, rolbypassrls FROM pg_roles WHERE rolname = current_user;"

db-postgres-migrate: venv
	@FG_DB_URL="$(APP_DB_URL)" FG_DB_BACKEND="postgres" $(PY) -m api.db_migrations --backend postgres --apply

db-postgres-assert: venv
	@FG_DB_URL="$(APP_DB_URL)" FG_DB_BACKEND="postgres" $(PY) -m api.db_migrations --backend postgres --assert

db-postgres-test: venv
	@FG_DB_URL="$(APP_DB_URL_COMPOSE)" FG_DB_BACKEND="postgres" FG_ENV=test $(PYTEST_ENV) $(PYTEST) -q tests/postgres -rs

db-postgres-verify: db-postgres-up db-postgres-migrate db-postgres-assert db-postgres-test

db-postgres-down:
	@docker compose stop postgres || true

# =============================================================================
# Live port guard + local server
# =============================================================================

.PHONY: fg-live-port-check fg-up fg-down fg-ready fg-health fg-logs

fg-live-port-check: venv
	@$(PY) scripts/fg_port_check.py "$(HOST)" "$(PORT)"

fg-up: venv fg-live-port-check
	@mkdir -p "$(FG_STATE_DIR)" "$(STATE_DIR)" "$(ARTIFACTS_DIR)"
	@$(FG_RUN) ./scripts/uvicorn_local.sh start
	@$(MAKE) -s fg-ready

fg-down:
	@$(FG_RUN) ./scripts/uvicorn_local.sh stop || true

fg-ready:
	@$(FG_RUN) ./scripts/uvicorn_local.sh check

fg-health: venv
	@curl -fsS "$(BASE_URL)/health" | $(PY) -m json.tool

fg-logs:
	@$(FG_RUN) ./scripts/uvicorn_local.sh logs $(or $(N),200)

# =============================================================================
# Integration tests + ITest harness
# =============================================================================

.PHONY: test-integration itest-db-reset itest-up itest-down itest-local

test-integration: venv
	@set -euo pipefail; \
	BASE_URL="$${BASE_URL:-$(ITEST_BASE_URL)}"; \
	FG_SQLITE_PATH="$${FG_SQLITE_PATH:-$(ITEST_DB)}"; \
	FG_API_KEY="$${FG_API_KEY:-$(FG_API_KEY)}"; \
	export BASE_URL FG_SQLITE_PATH FG_API_KEY; \
	curl -fsS "$${BASE_URL}/health" >/dev/null || ( \
		echo "❌ API not reachable at BASE_URL=$${BASE_URL}"; \
		echo "   Start it with: make itest-up  (or run: make itest-local)"; \
		exit 1; \
	); \
	rc=0; \
	FG_BASE_URL="$${BASE_URL}" $(PYTEST_ENV) $(PYTEST) -q -m integration || rc=$$?; \
	if [ $$rc -eq 5 ]; then \
		echo "⚠️  No integration tests collected (ok for now)"; \
		exit 0; \
	fi; \
	exit $$rc

ITEST_HOST     ?= 127.0.0.1
ITEST_PORT     ?= 8001
ITEST_BASE_URL ?= http://$(ITEST_HOST):$(ITEST_PORT)
ITEST_DB       ?= $(CURDIR)/$(STATE_DIR)/frostgate-itest.db
ITEST_WIPE_DB  ?= 1

itest-db-reset: venv
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

ci: venv pip-audit fg-fast-ci
ci-integration: venv itest-local

pip-audit: venv
	@echo "==> running pip-audit"
	@$(PIP) install -q --upgrade pip-audit
	@$(PY) -m pip_audit -r requirements.txt -r requirements-dev.txt
	@$(PY) -m pip_audit -r admin_gateway/requirements.txt -r admin_gateway/requirements-dev.txt

# =============================================================================
# Evidence
# =============================================================================

EVIDENCE_SCENARIO ?= $(or $(SCENARIO),spike)

.PHONY: evidence ci-evidence

evidence: venv
	@set -euo pipefail; \
	test -n "$${BASE_URL:-}" || (echo "❌ BASE_URL required" && exit 1); \
	test -n "$${FG_API_KEY:-}" || (echo "❌ FG_API_KEY required" && exit 1); \
	test -n "$${FG_SQLITE_PATH:-}" || (echo "❌ FG_SQLITE_PATH required" && exit 1); \
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
	SCENARIO="$${SCENARIO:-spike}" BASE_URL="$(ITEST_BASE_URL)" FG_API_KEY="$(FG_API_KEY)" FG_SQLITE_PATH="$(ITEST_DB)" $(MAKE) -s evidence

# =============================================================================
# PT lane + hardening suites
# =============================================================================

.PHONY: ci-pt test-core-invariants test-decision-unified test-tenant-isolation test-auth-hardening test-dashboard-p0 test-hardening-all ci-hardening

ci-pt: venv _require-pytest-venv
	@FG_ENV=test $(PYTEST_ENV) $(PYTEST) -q tests/test_security_hardening.py tests/test_security_middleware.py

test-core-invariants: venv _require-pytest-venv
	@echo "Running core invariant tests (INV-001 through INV-007)."
	@FG_ENV=test $(PYTEST_ENV) $(PYTEST) -v tests/test_core_invariants.py tests/test_ui_dashboards.py

test-decision-unified: venv _require-pytest-venv
	@FG_ENV=test $(PYTEST_ENV) $(PYTEST) -q tests/test_decision_pipeline_unified.py

test-tenant-isolation: venv _require-pytest-venv
	@FG_ENV=test $(PYTEST_ENV) $(PYTEST) -q tests/test_tenant_invariant.py tests/test_auth_tenants.py

test-auth-hardening: venv _require-pytest-venv
	@FG_ENV=test $(PYTEST_ENV) $(PYTEST) -q \
		tests/test_auth_hardening.py tests/test_auth.py tests/test_auth_contract.py \
		tests/security/test_evidence_chain_persistence.py tests/security/test_chain_verification_detects_tamper.py \
		tests/security/test_scope_enforcement.py tests/security/test_key_hashing_kdf.py

test-dashboard-p0: venv _require-pytest-venv
	@FG_ENV=test $(PYTEST_ENV) $(PYTEST) -q tests/security/test_dashboard_p0_hardening.py tests/security/test_admin_audit_required_fields.py

test-hardening-all: test-core-invariants test-decision-unified test-tenant-isolation test-auth-hardening test-dashboard-p0
	@echo "✅ All hardening tests passed"

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
AG_REQS_STAMP := $(AG_VENV)/.requirements.sha256

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

admin-venv:
	@set -euo pipefail; \
	echo "Admin venv: $(AG_VENV) (python: $$(command -v $(ADMIN_PY)))"; \
	command -v "$(ADMIN_PY)"; \
	"$(ADMIN_PY)" -V; \
	"$(ADMIN_PY)" -m venv --upgrade "$(AG_VENV)"; \
	if [ "$${ADMIN_SKIP_PIP_INSTALL:-0}" = "1" ]; then \
		echo "Skipping admin-gateway package install (ADMIN_SKIP_PIP_INSTALL=1)"; \
		exit 0; \
	fi; \
	REQS_HASH=$$(cat admin_gateway/requirements.txt admin_gateway/requirements-dev.txt 2>/dev/null | sha256sum | cut -d' ' -f1); \
	STAMP_HASH=$$(cat "$(AG_REQS_STAMP)" 2>/dev/null || echo "none"); \
	if [ "$$REQS_HASH" = "$$STAMP_HASH" ]; then \
		echo "Admin-gateway deps unchanged (stamp match), skipping pip install."; \
		if command -v ruff >/dev/null 2>&1 && [ ! -x "$(AG_VENV)/bin/ruff" ]; then \
			ln -sf "$$(command -v ruff)" "$(AG_VENV)/bin/ruff"; \
		fi; \
		exit 0; \
	fi; \
	echo "Installing admin-gateway dependencies into $(AG_VENV)."; \
	env -u HTTP_PROXY -u http_proxy -u HTTPS_PROXY -u https_proxy $(AG_PIP_ENV) "$(AG_PIP)" install --upgrade pip; \
	env -u HTTP_PROXY -u http_proxy -u HTTPS_PROXY -u https_proxy $(AG_PIP_ENV) "$(AG_PIP)" install -c constraints.txt -r admin_gateway/requirements.txt -r admin_gateway/requirements-dev.txt; \
	echo "$$REQS_HASH" > "$(AG_REQS_STAMP)"; \
	if command -v ruff >/dev/null 2>&1 && [ ! -x "$(AG_VENV)/bin/ruff" ]; then \
		ln -sf "$$(command -v ruff)" "$(AG_VENV)/bin/ruff"; \
	fi

admin-venv-check:
	@set -euo pipefail; \
	test -x "$(AG_PY)" || (echo "Admin venv not ready: $(AG_PY) not found" && exit 1); \
	echo "Admin venv OK: $(AG_PY)"; \
	"$(AG_PY)" -V

admin-dev: admin-venv
	@echo "Starting admin-gateway on $(AG_BASE_URL)..."
	@PYTHONPATH=. FG_ENV=dev $(AG_PY) -m uvicorn admin_gateway.asgi:app --host $(AG_HOST) --port $(AG_PORT) --reload

admin-lint: admin-venv
	@set -euo pipefail; \
	if [ "$${ADMIN_SKIP_PIP_INSTALL:-0}" = "1" ]; then \
		$(RUFF) check admin_gateway; \
		$(RUFF) format --check admin_gateway; \
	else \
		$(AG_PY) -m ruff check admin_gateway; \
		$(AG_PY) -m ruff format --check admin_gateway; \
	fi

admin-test: admin-venv
	@set -euo pipefail; \
	if [ "$${ADMIN_SKIP_PIP_INSTALL:-0}" = "1" ]; then \
		PYTHONPATH=. $(PYTEST_ENV) $(PYTEST) admin_gateway/tests -q; \
	else \
        FG_DEV_TENANT_ID="$${FG_DEV_TENANT_ID:-$(FG_DEV_TENANT_ID)}" FG_DEV_ALLOWED_TENANTS="$${FG_DEV_ALLOWED_TENANTS:-$(FG_DEV_ALLOWED_TENANTS)}" PYTHONPATH=. $(PYTEST_ENV) $(AG_VENV)/bin/pytest admin_gateway/tests -q; \
	fi

ci-admin: admin-venv admin-lint admin-test

# =============================================================================
# Compliance Gates
# =============================================================================

.PHONY: compliance-sbom compliance-provenance compliance-cis compliance-scap compliance-all

compliance-sbom: venv
	@mkdir -p "$(ARTIFACTS_DIR)"
	@$(PY) scripts/generate_sbom.py -o "$(ARTIFACTS_DIR)/sbom.json"

compliance-provenance: venv
	@mkdir -p "$(ARTIFACTS_DIR)"
	@$(PY) scripts/provenance.py -o "$(ARTIFACTS_DIR)/provenance.json"

compliance-cis: venv
	@mkdir -p "$(ARTIFACTS_DIR)"
	@$(PY) scripts/cis_check.py -o "$(ARTIFACTS_DIR)/cis_check.json" --fail-threshold 70

compliance-scap: venv
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

# =============================================================================
# Repo guards
# =============================================================================

.PHONY: guard-no-trash paste-garbage guard deps-up deps-down fg-restart

guard-no-trash:
	@bad=$$(git ls-files | grep -E '^(agent_queue/|keys/|secrets/|state/|artifacts/|logs/|CONTEXT_SNAPSHOT\.md|supervisor-sidecar/supervisor-sidecar)' || true); \
	if [ -n "$$bad" ]; then \
	  echo "Forbidden tracked paths:"; echo "$$bad"; exit 1; \
	fi

paste-garbage: guard-no-trash
	@echo "paste-garbage guard: OK"

guard: guard-scripts guard-no-trash
	@echo "guard: OK"

deps-up:
	@command -v docker >/dev/null 2>&1 || (echo "❌ docker missing" && exit 1)
	@docker ps >/dev/null 2>&1 || (echo "Docker not running" && exit 1)
	@docker inspect fg-redis >/dev/null 2>&1 || \
	  docker run -d --name fg-redis -p 6379:6379 redis:7
	@echo "✅ deps up (redis on :6379)"

deps-down:
	@docker rm -f fg-redis >/dev/null 2>&1 || true
	@echo "✅ deps down"

fg-restart:
	@$(MAKE) -s fg-down || true
	@$(MAKE) -s fg-up

# =============================================================================
# PR Parity Checks (run locally what PR runs)
# =============================================================================

.PHONY: pr-check pr-check-all pr-check-ci pr-check-verify-targets
.PHONY: pr-check-fast pr-check-lint pr-check-test pr-check-contract pr-check-prod

__mkdb__:

makefile-sanity: guard-scripts
	@echo "Makefile sanity: OK"

pr-check-fast:
	@$(MAKE) -s fg-fast
	@echo "pr-check-fast: OK"

pr-check-lint:
	@$(MAKE) -s fg-lint
	@$(MAKE) -s test-dashboard-p0
	@echo "pr-check-lint: OK"

pr-check-test: venv
	@$(MAKE) -s test-unit
	@echo "pr-check-test: OK"

pr-check-contract:
	@$(MAKE) -s fg-contract
	@echo "pr-check-contract: OK"

pr-check-prod: venv
	@$(MAKE) -s opa-check prod-profile-check prod-unsafe-config-check audit-chain-verify dos-hardening-check gap-audit
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

pr-check: pr-check-verify-targets paste-garbage pr-check-fast
	@echo "✅ pr-check: PASS"

pr-check-all: pr-check
	@$(MAKE) -s release-gate
	@echo "✅ pr-check-all (includes release-gate): PASS"

pr-check-ci: pr-check-all
	@echo "✅ pr-check-ci: PASS"

.PHONY: codex-check
codex-check: venv
	@$(MAKE) -s pr-check

# =============================================================================
# SOC manifest
# =============================================================================

.PHONY: soc-manifest-sync soc-manifest-verify

soc-manifest-sync: venv
	@PYTHONPATH=. $(PY) tools/ci/sync_soc_manifest_status.py --mode sync --write

soc-manifest-verify: venv
	@PYTHONPATH=. $(PY) tools/ci/sync_soc_manifest_status.py --mode verify --fail-on-unresolved-p0

# =============================================================================
# SQL migration percent guard (psycopg3 hazard)
# =============================================================================

.PHONY: sql-migration-percent-guard
sql-migration-percent-guard: venv _require-venv
	@PYTHONPATH=. $(PY) tools/ci/guard_no_raw_percent_in_sql.py

# =============================================================================
# Postgres dev helpers (single definition, no duplicates)
# =============================================================================

.PHONY: pg-reset-frostgate test-pg-migrations-replay

pg-reset-frostgate:
	@bash tools/dev/reset_postgres_db.sh frostgate

test-pg-migrations-replay: pg-reset-frostgate venv _require-pytest-venv
	@FG_DB_URL=$${FG_DB_URL:-postgresql+psycopg://fg_user:fg_password@127.0.0.1:5432/frostgate} \
	$(PYTEST) -q tests/test_migrations_postgres_replay.py::test_postgres_migrations_replay_safe

route-inventory-update:
	@$(MAKE) route-inventory-generate
	@$(MAKE) route-inventory-audit
	@echo "✅ route inventory updated; commit tools/ci/route_inventory.json"

.PHONY: compliance-cp-spot enterprise-controls-spot breakglass-spot governance-risk-spot evidence-anchor-spot federation-spot

compliance-cp-spot: venv _require-pytest-venv
	@FG_ENV=test $(PYTEST_ENV) $(PYTEST) -q tests/test_enterprise_extensions.py -k compliance_cp

enterprise-controls-spot: venv _require-pytest-venv
	@FG_ENV=test $(PYTEST_ENV) $(PYTEST) -q tests/test_enterprise_extensions.py -k enterprise_controls

breakglass-spot: venv _require-pytest-venv
	@FG_ENV=test $(PYTEST_ENV) $(PYTEST) -q tests/test_enterprise_extensions.py -k breakglass

governance-risk-spot: venv _require-pytest-venv
	@FG_ENV=test $(PYTEST_ENV) $(PYTEST) -q tests/test_enterprise_extensions.py -k governance_risk

evidence-anchor-spot: venv _require-pytest-venv
	@FG_ENV=test $(PYTEST_ENV) $(PYTEST) -q tests/test_enterprise_extensions.py -k evidence_anchor

federation-spot: venv _require-pytest-venv
	@FG_ENV=test $(PYTEST_ENV) $(PYTEST) -q tests/test_enterprise_extensions.py -k federation

.PHONY: ai-plane-spot
ai-plane-spot: venv _require-pytest-venv
	@FG_ENV=test $(PYTEST_ENV) $(PYTEST) -q tests/test_ai_plane_extension.py

.PHONY: enterprise-ext-spot ai-plane-full enterprise-smoke

enterprise-ext-spot: compliance-cp-spot enterprise-controls-spot breakglass-spot governance-risk-spot evidence-anchor-spot federation-spot

ai-plane-full: venv _require-pytest-venv
	@FG_ENV=test FG_AI_PLANE_ENABLED=1 FG_AI_EXTERNAL_PROVIDER_ENABLED=0 $(PYTEST_ENV) $(PYTEST) -q tests/test_ai_plane_extension.py
	@FG_ENV=test FG_AI_PLANE_ENABLED=1 FG_AI_EXTERNAL_PROVIDER_ENABLED=0 $(PY) scripts/generate_ai_plane_evidence.py
	@FG_ENV=test FG_AI_PLANE_ENABLED=1 FG_AI_EXTERNAL_PROVIDER_ENABLED=0 $(PYTEST_ENV) $(PYTEST) -q tests/test_ai_plane_extension.py::test_ai_artifact_generation_schema_validation
	@$(MAKE) route-inventory-audit

enterprise-smoke: venv
	@FG_ENV=test FG_AI_PLANE_ENABLED=1 FG_AI_EXTERNAL_PROVIDER_ENABLED=0 $(PY) scripts/run_enterprise_smoke.py


.PHONY: openapi-security-diff
openapi-security-diff: venv
	@$(PY) tools/ci/check_openapi_security_diff.py

.PHONY: plane-registry-spot evidence-index-spot resilience-smoke nuclear-full governance-invariants

plane-registry-spot: venv
	@$(PY) tools/ci/check_plane_registry.py
	@FG_ENV=test $(PYTEST_ENV) $(PYTEST) -q tests/test_plane_registry.py

evidence-index-spot: venv _require-pytest-venv
	@FG_ENV=test $(PYTEST_ENV) $(PYTEST) -q tests/test_evidence_index.py

resilience-smoke: venv _require-pytest-venv
	@FG_ENV=test FG_DEGRADED_MODE=1 FG_BACKPRESSURE_ENABLED=1 $(PYTEST_ENV) $(PYTEST) -q tests/test_resilience_guard.py tests/test_self_heal_watchdog.py

governance-invariants: venv
	@$(PY) tools/ci/check_governance_invariants.py

nuclear-full: venv
	@$(MAKE) route-inventory-generate
	@$(MAKE) route-inventory-audit
	@$(MAKE) contract-authority-refresh
	@$(MAKE) fg-contract
	@$(MAKE) plane-registry-spot
	@$(MAKE) evidence-index-spot
	@$(MAKE) enterprise-ext-spot
	@$(MAKE) ai-plane-spot
	@$(MAKE) ai-plane-full
	@$(MAKE) resilience-smoke
	@$(MAKE) governance-invariants
	@$(MAKE) openapi-security-diff
	@$(MAKE) platform-inventory
	@$(MAKE) openapi-summary
	@$(MAKE) enterprise-smoke


.PHONY: pr-merge-smoke
pr-merge-smoke: venv
	@mkdir -p artifacts
	@ruff check
	@$(PYTEST) -q
	@$(MAKE) route-inventory-generate
	@$(MAKE) route-inventory-audit
	@$(MAKE) contract-authority-refresh
	@$(MAKE) fg-contract
	@$(MAKE) platform-inventory
	@$(MAKE) openapi-summary
	@$(MAKE) nuclear-full


.PHONY: platform-inventory openapi-summary
platform-inventory: venv
	@$(PY) scripts/generate_platform_inventory.py

openapi-summary: venv
	@$(PY) scripts/summarize_openapi_changes.py
