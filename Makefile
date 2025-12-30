# Makefile
SHELL := /bin/bash
.SHELLFLAGS := -lc
.ONESHELL:
.DELETE_ON_ERROR:

# -----------------------------------------------------------------------------
# Image coordinates
# -----------------------------------------------------------------------------
REGISTRY        ?= ghcr.io
IMAGE_OWNER     ?= your-org-or-user
CORE_IMAGE_NAME ?= frostgate-core
SIDE_IMAGE_NAME ?= frostgate-supervisor-sidecar

CORE_IMAGE      := $(REGISTRY)/$(IMAGE_OWNER)/$(CORE_IMAGE_NAME)
SIDE_IMAGE      := $(REGISTRY)/$(IMAGE_OWNER)/$(SIDE_IMAGE_NAME)

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)

# -----------------------------------------------------------------------------
# Python / venv
# -----------------------------------------------------------------------------
VENV    ?= .venv
PYTHON  ?= $(VENV)/bin/python
PIP     ?= $(VENV)/bin/pip
export PYTHONPATH := .

# -----------------------------------------------------------------------------
# Runtime defaults (single source of truth)
# -----------------------------------------------------------------------------
HOST            ?= 127.0.0.1
PORT            ?= 8001
BASE_URL        ?= http://$(HOST):$(PORT)

FG_ENV          ?= dev
FG_SERVICE      ?= frostgate-core

FG_AUTH_ENABLED ?= 1
FG_API_KEY      ?= demo_key_change_me
FG_ENFORCEMENT_MODE ?= observe

# IMPORTANT: keep these RELATIVE by default to avoid DB drift between server/tests.
STATE_DIR       ?= state
FG_SQLITE_PATH  ?= $(STATE_DIR)/frostgate.db

# Mirror legacy
export API_KEY := $(FG_API_KEY)

ARTIFACTS_DIR   ?= artifacts
EVIDENCE_DIR    ?= $(ARTIFACTS_DIR)/evidence
SCENARIO        ?= spike

SQLITE_ABS := $(abspath $(FG_SQLITE_PATH))

# -----------------------------------------------------------------------------
# Env injector (DO NOT NAME THIS FG_ENV... that was your earlier footgun)
# -----------------------------------------------------------------------------
define FG_RUN
FG_ENV="$(FG_ENV)" \
FG_SERVICE="$(FG_SERVICE)" \
FG_AUTH_ENABLED="$(FG_AUTH_ENABLED)" \
FG_API_KEY="$(FG_API_KEY)" \
FG_ENFORCEMENT_MODE="$(FG_ENFORCEMENT_MODE)" \
FG_SQLITE_PATH="$(FG_SQLITE_PATH)" \
BASE_URL="$(BASE_URL)" \
HOST="$(HOST)" \
PORT="$(PORT)" \
API_KEY="$(FG_API_KEY)"
endef

# -----------------------------------------------------------------------------
# Help
# -----------------------------------------------------------------------------
.PHONY: help
help:
	@echo "Targets:"
	@echo "  make venv                 - create venv + install deps"
	@echo "  make test                 - unit lane (not integration)"
	@echo "  make test-smoke           - smoke lane"
	@echo "  make test-integration     - integration lane (requires running API)"
	@echo "  make test-e2e             - integration + e2e markers (requires running API)"
	@echo "  make test-all             - unit + integration + e2e"
	@echo "  make run-dev              - run API locally (uvicorn --reload)"
	@echo "  make stop-dev             - kill listeners bound to PORT"
	@echo "  make seed-spike|steady|drop - seed demo data + print stats summary"
	@echo "  make stats-summary        - print /stats/summary"
	@echo "  make demo                 - generate HTML report under artifacts/"
	@echo "  make evidence             - forensic evidence export + zip (+ optional signature)"
	@echo "  make e2e-local             - full local lane: unit -> start -> integration -> evidence -> stop"
	@echo ""
	@echo "Overrides: HOST=... PORT=... BASE_URL=... FG_API_KEY=... FG_SQLITE_PATH=state/frostgate.db SCENARIO=spike"

# -----------------------------------------------------------------------------
# Local Dev
# -----------------------------------------------------------------------------
.PHONY: venv
venv:
	test -d "$(VENV)" || python -m venv "$(VENV)"
	"$(PIP)" install --upgrade pip
	"$(PIP)" install -r requirements.txt -r requirements-dev.txt

# -----------------------------------------------------------------------------
# Tests
# -----------------------------------------------------------------------------
.PHONY: test
test:
	"$(PYTHON)" -m pytest -q -m "not integration"

.PHONY: test-sanity
test-sanity:
	"$(PYTHON)" -c "import pytest, pytest_asyncio, pytest_env; print('pytest', pytest.__version__, 'pytest_asyncio', pytest_asyncio.__version__)"
	$(MAKE) test

.PHONY: test-smoke
test-smoke:
	"$(PYTHON)" -m pytest -q -m smoke

.PHONY: test-integration
test-integration: server-check
	@$(FG_RUN) "$(PYTHON)" -m pytest -q -m integration

.PHONY: test-e2e
test-e2e: server-check
	@$(FG_RUN) "$(PYTHON)" -m pytest -q -m "integration or e2e"

.PHONY: test-all
test-all: test test-integration test-e2e

.PHONY: test-demo
test-demo: test

# -----------------------------------------------------------------------------
# Server + seed utilities
# -----------------------------------------------------------------------------
.PHONY: server-check seed-wipe stats-summary seed seed-spike seed-steady seed-drop seed-%

server-check:
	@curl -fsS "$(BASE_URL)/health" >/dev/null || (echo "API not reachable at $(BASE_URL)" && exit 1)
	@curl -fsS -H "X-API-Key: $(FG_API_KEY)" "$(BASE_URL)/stats/summary" >/dev/null || (echo "API reachable but auth failed. Check FG_API_KEY / FG_AUTH_ENABLED." && exit 1)

seed-wipe:
	@test -n "$(FG_SQLITE_PATH)" || (echo "FG_SQLITE_PATH must be set" && exit 1)
	@mkdir -p "$(STATE_DIR)"
	@sqlite3 "$(FG_SQLITE_PATH)" "delete from decisions;" || true

stats-summary:
	@test -n "$(BASE_URL)" || (echo "BASE_URL must be set" && exit 1)
	@test -n "$(FG_API_KEY)" || (echo "FG_API_KEY must be set" && exit 1)
	@curl -fsS -H "X-API-Key: $(FG_API_KEY)" "$(BASE_URL)/stats/summary" | python -m json.tool

# Seed implementation (single codepath)
seed: server-check seed-wipe
	@test -n "$(SEED_MODE)" || (echo "SEED_MODE required (spike|steady|drop)" && exit 1)
	@mkdir -p "$(STATE_DIR)"
	@$(FG_RUN) SEED_MODE="$(SEED_MODE)" ./scripts/seed_demo_decisions.sh
	@$(MAKE) stats-summary

seed-spike:
	@$(MAKE) seed SEED_MODE=spike

seed-steady:
	@$(MAKE) seed SEED_MODE=steady

seed-drop:
	@$(MAKE) seed SEED_MODE=drop

# Convenience: seed-spike via "seed-spike" dependency naming used elsewhere
seed-%:
	@$(MAKE) seed SEED_MODE="$*"

# -----------------------------------------------------------------------------
# Build / CI
# -----------------------------------------------------------------------------
.PHONY: build
build:
	cd supervisor-sidecar && go build ./...

.PHONY: ci-tools
ci-tools:
	@command -v rg >/dev/null || (echo "❌ ripgrep (rg) missing" && exit 1)
	@command -v curl >/dev/null || (echo "❌ curl missing" && exit 1)
	@command -v sqlite3 >/dev/null || (echo "❌ sqlite3 missing" && exit 1)
	@command -v zip >/dev/null || (echo "❌ zip missing" && exit 1)
	@command -v go >/dev/null || (echo "❌ go missing" && exit 1)
	@echo "✅ CI tools present"

.PHONY: guard-no-8000
guard-no-8000:
	@rg -n "127\.0\.0\.1:8000|:8000\b" scripts api tests *.py *.sh 2>/dev/null && \
	 (echo "❌ Hardcoded :8000 found. Use BASE_URL env." && exit 1) || \
	 echo "✅ No hardcoded :8000 found"

.PHONY: ci
ci: ci-tools guard-no-8000 test-sanity build

# -----------------------------------------------------------------------------
# Docker
# -----------------------------------------------------------------------------
.PHONY: docker-build docker-push docker-release
docker-build:
	docker build \
		-t $(CORE_IMAGE):$(VERSION) \
		-t $(CORE_IMAGE):latest \
		.
	docker build \
		-t $(SIDE_IMAGE):$(VERSION) \
		-t $(SIDE_IMAGE):latest \
		supervisor-sidecar

docker-push:
	docker push $(CORE_IMAGE):$(VERSION)
	docker push $(CORE_IMAGE):latest
	docker push $(SIDE_IMAGE):$(VERSION)
	docker push $(SIDE_IMAGE):latest

docker-release: docker-build docker-push

.PHONY: docker-build-local docker-run docker-shell
docker-build-local:
	docker build -t frostgate-core:local .

docker-run:
	docker run --rm -p 8080:8080 \
	  -e FG_ENV=dev \
	  -e FG_ENFORCEMENT_MODE=observe \
	  -e FG_AUTH_ENABLED=1 \
	  -e FG_API_KEY="$(FG_API_KEY)" \
	  -e FG_SQLITE_PATH=/state/frostgate.db \
	  frostgate-core:local

docker-shell:
	docker run --rm -it frostgate-core:local /bin/bash

# -----------------------------------------------------------------------------
# Tenant Tools
# -----------------------------------------------------------------------------
.PHONY: tenant-add tenant-list
tenant-add:
	@test -n "$(TENANT_ID)" || (echo "TENANT_ID is required" && exit 1)
	"$(PYTHON)" -m tools.tenants add "$(TENANT_ID)"

tenant-list:
	"$(PYTHON)" -m tools.tenants list

# -----------------------------------------------------------------------------
# Scripts (build/deploy)
# -----------------------------------------------------------------------------
.PHONY: build-dev build-prod deploy-dev deploy-prod
build-dev:
	ENVIRONMENT=dev PUSH_IMAGE=0 scripts/build.sh

build-prod:
	ENVIRONMENT=prod scripts/build.sh

deploy-dev:
	ENVIRONMENT=dev scripts/deploy_dev.sh

deploy-prod:
	ENVIRONMENT=prod VERSION=$(VERSION) scripts/deploy_prod.sh

# -----------------------------------------------------------------------------
# Run local API
# -----------------------------------------------------------------------------
.PHONY: port-check run-dev stop-dev quickcheck
port-check:
	@ss -ltn "sport = :$(PORT)" | rg -q LISTEN && \
		(echo "Port $(PORT) already in use. Kill the running server or run: make run-dev PORT=...." && exit 1) || true

run-dev: port-check
	@mkdir -p "$(STATE_DIR)"
	@echo "Starting FrostGate Core on $(BASE_URL)"
	@echo "Health:  curl -fsS $(BASE_URL)/health | python -m json.tool"
	@echo "Summary: curl -fsS -H 'X-API-Key: $(FG_API_KEY)' $(BASE_URL)/stats/summary | python -m json.tool"
	@$(FG_RUN) uvicorn api.main:app --host "$(HOST)" --port "$(PORT)" --reload

stop-dev:
	@pids=$$(sudo ss -ltnp "sport = :$(PORT)" 2>/dev/null | sed -n 's/.*pid=\([0-9]\+\).*/\1/p' | sort -u); \
	if [ -z "$$pids" ]; then echo "No listener on $(PORT)"; exit 0; fi; \
	echo "Killing listeners on $(PORT): $$pids"; \
	sudo kill -TERM $$pids 2>/dev/null || true; \
	sleep 1; \
	sudo kill -KILL $$pids 2>/dev/null || true

quickcheck: server-check
	@curl -fsS "$(BASE_URL)/health" | python -m json.tool
	@curl -fsS -H "X-API-Key: $(FG_API_KEY)" "$(BASE_URL)/stats/summary" | python -m json.tool

# -----------------------------------------------------------------------------
# Demo / Artifact lane
# -----------------------------------------------------------------------------
.PHONY: artifacts-dir demo demo-seed demo-report demo-open demo-clean
artifacts-dir:
	@mkdir -p "$(ARTIFACTS_DIR)"

demo: server-check artifacts-dir demo-seed demo-report
	@echo "✅ Demo complete: $(ARTIFACTS_DIR)"

demo-seed:
	@echo "Seeding scenario: $(SCENARIO)"
	@$(MAKE) seed SEED_MODE=$(SCENARIO)

demo-report:
	@ts=$$(date -u +%Y%m%dT%H%M%SZ); \
	out_dir="$(ARTIFACTS_DIR)/$${ts}_$(SCENARIO)"; \
	mkdir -p "$$out_dir"; \
	echo "Writing report -> $$out_dir"; \
	curl -fsS -H "X-API-Key: $(FG_API_KEY)" "$(BASE_URL)/health"        > "$$out_dir/health.json"; \
	curl -fsS -H "X-API-Key: $(FG_API_KEY)" "$(BASE_URL)/stats/summary" > "$$out_dir/summary.json"; \
	curl -fsS -H "X-API-Key: $(FG_API_KEY)" "$(BASE_URL)/stats"         > "$$out_dir/stats.json"; \
	printf '<html><head><meta charset="utf-8"><title>FrostGate Demo Report</title></head><body>' > "$$out_dir/report.html"; \
	printf '<h1>FrostGate Demo Report</h1><p><b>Scenario:</b> $(SCENARIO)</p><p><b>Generated:</b> %s</p>' "$$ts" >> "$$out_dir/report.html"; \
	printf '<h2>/stats/summary</h2><pre>' >> "$$out_dir/report.html"; \
	python -m json.tool < "$$out_dir/summary.json" >> "$$out_dir/report.html"; \
	printf '</pre><h2>/health</h2><pre>' >> "$$out_dir/report.html"; \
	python -m json.tool < "$$out_dir/health.json" >> "$$out_dir/report.html"; \
	printf '</pre><h2>/stats</h2><pre>' >> "$$out_dir/report.html"; \
	python -m json.tool < "$$out_dir/stats.json" >> "$$out_dir/report.html"; \
	printf '</pre></body></html>' >> "$$out_dir/report.html"; \
	echo "$$out_dir" > "$(ARTIFACTS_DIR)/latest.txt"; \
	echo "Latest report: $$out_dir/report.html"

demo-open:
	@dir=$$(cat "$(ARTIFACTS_DIR)/latest.txt" 2>/dev/null || true); \
	if [ -z "$$dir" ]; then echo "No latest report found. Run: make demo"; exit 1; fi; \
	xdg-open "$$dir/report.html" >/dev/null 2>&1 || true; \
	echo "Opened: $$dir/report.html"

demo-clean:
	rm -rf "$(ARTIFACTS_DIR)"

# -----------------------------------------------------------------------------
# Evidence Bundle (forensic demo export)
# -----------------------------------------------------------------------------
.PHONY: evidence evidence-prepare evidence-report evidence-sign evidence-zip evidence-open evidence-verify

evidence: evidence-prepare seed-$(SCENARIO) evidence-report evidence-sign evidence-zip
	@echo "✅ Evidence bundle complete:"
	@cat "$(ARTIFACTS_DIR)/latest_zip.txt"

evidence-prepare:
	@mkdir -p "$(ARTIFACTS_DIR)" "$(EVIDENCE_DIR)" "$(STATE_DIR)"
	@test -n "$(FG_SQLITE_PATH)" || (echo "FG_SQLITE_PATH must be set" && exit 1)
	@touch "$(FG_SQLITE_PATH)" || true

evidence-report: server-check
	@BASE_URL="$(BASE_URL)" \
	FG_API_KEY="$(FG_API_KEY)" \
	FG_SQLITE_PATH="$(FG_SQLITE_PATH)" \
	FG_AUTH_ENABLED="$(FG_AUTH_ENABLED)" \
	FG_ENFORCEMENT_MODE="$(FG_ENFORCEMENT_MODE)" \
	ARTIFACTS_DIR="$(ARTIFACTS_DIR)" \
	EVIDENCE_DIR="$(EVIDENCE_DIR)" \
	SCENARIO="$(SCENARIO)" \
	HOST="$(HOST)" \
	PORT="$(PORT)" \
	./scripts/evidence_report.sh

evidence-sign:
	@bash -lc '\
	  set -euo pipefail; \
	  out=$$(cat "$(ARTIFACTS_DIR)/latest_evidence_dir.txt"); \
	  test -f "$$out/manifest.sha256" || { echo "❌ manifest missing"; exit 1; }; \
	  if [ -n "$${MINISIGN_SECRET_KEY:-}" ]; then \
	    echo "Signing manifest.sha256"; \
	    printf "%s" "$$MINISIGN_SECRET_KEY" > /tmp/minisign.key; \
	    minisign -S -s /tmp/minisign.key -m "$$out/manifest.sha256"; \
	    rm -f /tmp/minisign.key; \
	    test -f "$$out/manifest.sha256.minisig" || { echo "❌ signature not created"; exit 1; }; \
	  else \
	    echo "MINISIGN_SECRET_KEY not set, skipping signature"; \
	  fi; \
	  echo "✅ Evidence manifest signing complete"; \
	'

evidence-zip:
	@bash -lc '\
	  set -euo pipefail; \
	  out=$$(cat "$(ARTIFACTS_DIR)/latest_evidence_dir.txt"); \
	  ts=$$(basename "$$out" | cut -d_ -f1); \
	  scen=$$(echo "$(SCENARIO)" | tr -d "[:space:]"); \
	  zipname="$(ARTIFACTS_DIR)/frostgate_evidence_$${ts}_$${scen}.zip"; \
	  rm -f "$$zipname"; \
	  (cd "$$out/.." && zip -r "../$$(basename "$$zipname")" "$$(basename "$$out")" >/dev/null); \
	  echo "$$zipname" > "$(ARTIFACTS_DIR)/latest_zip.txt"; \
	  echo "$$zipname" > "$(ARTIFACTS_DIR)/latest_zip_$${scen}.txt"; \
	  ls -lh "$$zipname"; \
	'

evidence-open:
	@bash -lc '\
	  out=$$(cat "$(ARTIFACTS_DIR)/latest_evidence_dir.txt" 2>/dev/null || true); \
	  test -n "$$out" || (echo "No latest evidence dir. Run: make evidence SCENARIO=spike" && exit 1); \
	  ls -lah "$$out"; \
	'

evidence-verify:
	@bash -lc '\
	  set -euo pipefail; \
	  zip=$$(cat "$(ARTIFACTS_DIR)/latest_zip.txt"); \
	  tmp=$$(mktemp -d); \
	  unzip -q "$$zip" -d "$$tmp"; \
	  dir=$$(find "$$tmp" -maxdepth 2 -type d -name "*_$(SCENARIO)" | head -n1); \
	  test -n "$$dir" || (echo "❌ evidence dir not found in zip" && exit 1); \
	  (cd "$$dir" && sha256sum -c manifest.sha256); \
	  echo "✅ manifest verified"; \
	  rm -rf "$$tmp"; \
	'

# -----------------------------------------------------------------------------
# Full local E2E lane (no copy/paste disasters)
# -----------------------------------------------------------------------------
.PHONY: e2e-local e2e-start e2e-stop e2e-wait
e2e-start:
	@mkdir -p "$(STATE_DIR)" "$(ARTIFACTS_DIR)"
	@if [ -f "$(ARTIFACTS_DIR)/uvicorn.pid" ]; then kill "$$(cat "$(ARTIFACTS_DIR)/uvicorn.pid")" 2>/dev/null || true; fi
	@nohup bash -lc '\
	  set -e; \
	  $(FG_RUN) uvicorn api.main:app --host "$(HOST)" --port "$(PORT)" \
	' > "$(ARTIFACTS_DIR)/uvicorn.log" 2>&1 & echo $$! > "$(ARTIFACTS_DIR)/uvicorn.pid"
	@echo "Started uvicorn pid=$$(cat "$(ARTIFACTS_DIR)/uvicorn.pid") log=$(ARTIFACTS_DIR)/uvicorn.log"

e2e-wait:
	@for i in $$(seq 1 60); do \
	  curl -fsS "$(BASE_URL)/health" >/dev/null && exit 0; \
	  sleep 0.5; \
	done; \
	echo "API failed to come up. Tail logs:"; tail -200 "$(ARTIFACTS_DIR)/uvicorn.log" || true; exit 1

e2e-stop:
	@if [ -f "$(ARTIFACTS_DIR)/uvicorn.pid" ]; then kill "$$(cat "$(ARTIFACTS_DIR)/uvicorn.pid")" 2>/dev/null || true; fi

e2e-local: test e2e-start e2e-wait test-integration evidence evidence-verify e2e-stop
	@echo "✅ e2e-local complete"


.PHONY: guard-no-pytest-detection
guard-no-pytest-detection:
	@rg -n "_running_under_pytest|PYTEST_CURRENT_TEST|sys\.modules\['pytest'\]" api/main.py >/dev/null && \
	 (echo "❌ Pytest-detection found in api/main.py. Remove test hacks." && exit 1) || \
	 echo "✅ No pytest-detection in api/main.py"

ci: ci-tools guard-no-8000 guard-no-pytest-detection test-sanity build
