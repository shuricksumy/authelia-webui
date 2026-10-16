SHELL := /bin/bash
AUTHELIA_VERSION := $(shell scripts/authelia_version.sh)
export AUTHELIA_VERSION
# Containers run as you, so files in the (gitignored) generated stack stay removable.
export DEV_UID := $(shell id -u)
export DEV_GID := $(shell id -g)
COMPOSE := docker compose -f compose.test.yml

.PHONY: help version sync fixtures stack dev totp dev-logs dev-down test test-integration test-e2e lint hygiene scan screenshots image

help:
	@grep -E '^[a-z-]+:' Makefile | cut -d: -f1 | tr '\n' ' '; echo

version: ## pinned Authelia version (Dockerfile ARG is the single source)
	@echo $(AUTHELIA_VERSION)

sync:
	uv sync

fixtures: ## generate realistic test config with real secrets (gitignored)
	uv run python -m tests.fixtures.generate

stack: ## generate the compose test stack's files: config, TLS, Traefik, alice's TOTP (gitignored)
	uv run python -m tests.fixtures.stack

dev: stack ## full local stack with hot reload: Traefik + Authelia + the app (then: make totp)
	TEST_APP_SECRET_KEY=$$(openssl rand -base64 48) $(COMPOSE) -f compose.dev.yml up -d --build --wait --wait-timeout 240
	@echo
	@uv run python -m tests.fixtures.totp
	@echo
	@echo "Logs: make dev-logs      Stop: make dev-down"

totp: ## print the dev login: URL, user, password and the current 2FA code
	@uv run python -m tests.fixtures.totp

dev-logs:
	TEST_APP_SECRET_KEY=x $(COMPOSE) logs -f --tail=50 configurator authelia traefik

dev-down:
	TEST_APP_SECRET_KEY=x $(COMPOSE) down -v --remove-orphans

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

screenshots: stack ## capture every screen at 1280/390 px, light/dark, into docs/screenshots/
	TEST_APP_SECRET_KEY=$$(openssl rand -base64 48) $(COMPOSE) up -d --build --wait --wait-timeout 240
	uv run python -m tests.e2e.screenshots; rc=$$?; TEST_APP_SECRET_KEY=x $(COMPOSE) down -v --remove-orphans; exit $$rc
