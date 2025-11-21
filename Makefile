# Makefile

# ---- Meta ----
SHELL := /bin/bash

# Image coordinates (override in CI if needed)
REGISTRY        ?= ghcr.io
IMAGE_OWNER     ?= your-org-or-user
CORE_IMAGE_NAME ?= frostgate-core
SIDE_IMAGE_NAME ?= frostgate-supervisor-sidecar

CORE_IMAGE      := $(REGISTRY)/$(IMAGE_OWNER)/$(CORE_IMAGE_NAME)
SIDE_IMAGE      := $(REGISTRY)/$(IMAGE_OWNER)/$(SIDE_IMAGE_NAME)

# Version from git; falls back to "dev"
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)

# Python env
VENV ?= .venv
PYTHON ?= $(VENV)/bin/python
PIP ?= $(VENV)/bin/pip

# ---- Local dev / test ----

.PHONY: venv
venv:
	test -d $(VENV) || python -m venv $(VENV)
	$(PIP) install --upgrade pip
	$(PIP) install -r requirements.txt -r requirements-dev.txt

.PHONY: test
test:  ## Run Python test suite
	PYTHONPATH=. $(PYTHON) -m pytest -q

.PHONY: ci
ci:  ## CI entrypoint: tests + sidecar build
	PYTHONPATH=. $(PYTHON) -m pytest -q
	cd supervisor-sidecar && go build ./...

# ---- Docker build / publish ----

.PHONY: docker-build
docker-build:  ## Build both images with VERSION tag
	docker build \
		-t $(CORE_IMAGE):$(VERSION) \
		-t $(CORE_IMAGE):latest \
		.
	docker build \
		-t $(SIDE_IMAGE):$(VERSION) \
		-t $(SIDE_IMAGE):latest \
		supervisor-sidecar

.PHONY: docker-push
docker-push:  ## Push both images (VERSION + latest)
	docker push $(CORE_IMAGE):$(VERSION)
	docker push $(CORE_IMAGE):latest
	docker push $(SIDE_IMAGE):$(VERSION)
	docker push $(SIDE_IMAGE):latest

.PHONY: docker-release
docker-release: docker-build docker-push  ## Build + push in one shot

# ---- Utility ----

.PHONY: print-version
print-version:
	@echo $(VERSION)

.PHONY: print-images
print-images:
	@echo "Core: $(CORE_IMAGE):$(VERSION)"
	@echo "Sidecar: $(SIDE_IMAGE):$(VERSION)"

.PHONY: tenant-add
tenant-add:  ## Create tenant: make tenant-add TENANT_ID=foo
	@test -n "$(TENANT_ID)" || (echo "TENANT_ID is required" && exit 1)
	PYTHONPATH=. $(PYTHON) -m tools.tenants add $(TENANT_ID)

.PHONY: tenant-list
tenant-list:  ## List tenants in registry
	PYTHONPATH=. $(PYTHON) -m tools.tenants list

.PHONY: docker-build docker-run docker-shell

docker-build:
\tdocker build -t frostgate-core:local .

docker-run:
\tdocker run --rm -p 8080:8080 \
\t  -e FROSTGATE_ENV=dev \
\t  -e FROSTGATE_ENFORCEMENT_MODE=observe \
\t  -e FROSTGATE_LOG_LEVEL=DEBUG \
\t  frostgate-core:local

docker-shell:
\tdocker run --rm -it frostgate-core:local /bin/bash

