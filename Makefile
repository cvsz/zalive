# Makefile — albert_server common tasks
# Usage: make <target>

.PHONY: help test lint security build run stop logs clean rotate-fairplay validate docker-build docker-up docker-down

# Default target
help:
	@echo "albert_server — Local Albert Activation Server"
	@echo ""
	@echo "Targets:"
	@echo "  test              Run all tests (pytest)"
	@echo "  lint              Run ruff linter"
	@echo "  security          Run bandit security scan"
	@echo "  check             Run lint + security + tests"
	@echo "  validate          Run production validation script"
	@echo "  build             Build Docker image"
	@echo "  up                Start services (docker compose up -d)"
	@echo "  down              Stop services (docker compose down)"
	@echo "  logs              Follow service logs"
	@echo "  run               Run server locally (requires .env)"
	@echo "  rotate-fairplay   Rotate FairPlay keys (certs/fairplay.*)"
	@echo "  clean             Remove build artifacts, caches, logs"
	@echo "  help              Show this help"

# Testing
test:
	pytest -q

test-verbose:
	pytest -v

test-ci:
	ALBERT_ADMIN_TOKEN=ci-test-token ALBERT_ACCEPT_RISK=1 pytest -q --ignore=tests/test_bootstrap.py

# Linting
lint:
	ruff check .

lint-fix:
	ruff check . --fix

# Security
security:
	bandit -r . --exclude ./venv -q

security-verbose:
	bandit -r . --exclude ./venv

# Combined checks
check: lint security test

# Validation
validate:
	ALBERT_ADMIN_TOKEN=ci-test-token ALBERT_ACCEPT_RISK=1 python3 scripts/validate.py

# Docker
docker-build:
	docker build -t albert-server:local .

docker-config:
	docker compose config

up:
	docker compose up -d

down:
	docker compose down

down-volumes:
	docker compose down -v

logs:
	docker compose logs -f

logs-albert:
	docker compose logs -f albert-server

logs-mitm:
	docker compose logs -f mitmproxy

# Local run (requires .env with ALBERT_ACCEPT_RISK=1)
run:
	@if [ ! -f .env ]; then echo "ERROR: .env not found. cp .env.example .env"; exit 1; fi
	@if ! grep -q "ALBERT_ACCEPT_RISK=1" .env; then echo "ERROR: ALBERT_ACCEPT_RISK=1 required in .env"; exit 1; fi
	python3 albert_server.py --host 0.0.0.0 --port 18090

run-https:
	@if [ ! -f .env ]; then echo "ERROR: .env not found"; exit 1; fi
	python3 albert_server.py --host 0.0.0.0 --port 18443 --ssl-cert certs/server.crt --ssl-key certs/server.key

# FairPlay key rotation
rotate-fairplay:
	python3 albert_server.py --rotate-fairplay

# Cleanup
clean:
	rm -rf __pycache__ .pytest_cache .ruff_cache .mypy_cache
	rm -rf logs/*.log certs/*.key certs/*.crt 2>/dev/null || true
	find . -name "*.pyc" -delete
	find . -name "*.pyo" -delete
	find . -name "*~" -delete

clean-all: clean
	docker compose down -v --rmi local 2>/dev/null || true
	docker image prune -f

# Development helpers
shell:
	docker compose exec albert-server bash

shell-mitm:
	docker compose exec mitmproxy bash

db-shell:
	sqlite3 logs/activations.db

# Generate admin token
gen-token:
	@python3 -c "import secrets; print(secrets.token_urlsafe(32))"

gen-mitm-password:
	@python3 -c "import secrets; print(secrets.token_urlsafe(16))"