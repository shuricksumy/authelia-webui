SHELL := /bin/bash
AUTHELIA_VERSION := $(shell scripts/authelia_version.sh)
export AUTHELIA_VERSION

.PHONY: help version sync fixtures stack dev test test-integration test-e2e lint hygiene scan screenshots image

help:
	@grep -E '^[a-z-]+:' Makefile | cut -d: -f1 | tr '\n' ' '; echo

version: ## pinned Authelia version (Dockerfile ARG is the single source)
	@echo $(AUTHELIA_VERSION)

sync:
	uv sync

fixtures: ## generate realistic test config with real secrets (gitignored)
	uv run python -m tests.fixtures.generate

stack: ## generate the compose test stack's /config (gitignored)
	uv run python -m tests.fixtures.stack

dev: stack ## test stack with rebuild on change (portal: http://auth.example.com:19091 via hosts/resolver rule)
	TEST_APP_SECRET_KEY=$$(openssl rand -base64 48) docker compose -f compose.test.yml up --build

test: ## unit tests
	uv run pytest tests/unit

test-integration: ## needs Docker; runs the real pinned Authelia
	uv run pytest tests/integration -m integration -o testpaths=tests/integration

test-e2e: ## needs the compose test stack
	uv run pytest tests/e2e -m e2e -o testpaths=tests/e2e

lint: hygiene
	uv run ruff check .
	uv run ruff format --check .
	uv run mypy

hygiene: ## public-repo hygiene (no real domains/IPs/hashes/PEM)
	uv run python -m scripts.check_public_hygiene

GITLEAKS_IMAGE := zricethezav/gitleaks:v8.30.1
TRIVY_IMAGE := aquasec/trivy:latest

scan: hygiene ## secret + image scan (tools run from pinned/official images, no local install)
	docker run --rm -v "$$PWD:/repo" $(GITLEAKS_IMAGE) git /repo --no-banner --redact --exit-code 1
	docker build -t authelia-configurator:scan --build-arg AUTHELIA_VERSION=$(AUTHELIA_VERSION) .
	docker save authelia-configurator:scan -o .scan-image.tar
	docker run --rm -v "$$PWD/.scan-image.tar:/image.tar:ro" $(TRIVY_IMAGE) image --input /image.tar \
		--severity CRITICAL --ignore-unfixed --exit-code 1; rc=$$?; rm -f .scan-image.tar; exit $$rc

image:
	docker build -t authelia-configurator:dev --build-arg AUTHELIA_VERSION=$(AUTHELIA_VERSION) .

screenshots: ## UI screenshots (no UI until Phase 1)
	@echo "No UI in Phase 0; implemented with the Phase 1 UI."; exit 1
