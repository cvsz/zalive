SHELL := /bin/sh

.PHONY: help validate validate-template setup format lint test build security ci trivy

help:
	@printf '%s\n' 'validate: full production validate (IPSW/FairPlay/DB/env/API/logs)' 'validate-template: legacy unittest' 'test: pytest' 'lint: ruff' 'security: bandit' 'ci: validate lint test security' 'Bootstrap: python3 scripts/bootstrap.py --help' 'Security: trivy'

validate:
	@mkdir -p logs logs/restore
	./scripts/sha256_manifest.sh --check
	python3 -m py_compile albert_server.py activate_device.py firmware_restore_proxy.py
	ruff check .
	python3 -m pytest -q --ignore=tests/test_bootstrap.py
	python3 scripts/validate.py

validate-template:
	python3 -m unittest discover -s tests -v

setup:
	python3 -m venv venv || true
	./venv/bin/pip install -r requirements.txt
	cp -n .env.example .env || true
	@echo "setup done — edit .env ALBERT_ADMIN_TOKEN and ALBERT_ACCEPT_RISK=1"

format:
	ruff check --fix . || true
	ruff format . || true

lint:
	ruff check .

test:
	python -m pytest -q --ignore=tests/test_bootstrap.py

security:
	bandit -r . --exclude ./venv -q

build:
	docker compose config > /dev/null
	python3 -m py_compile albert_server.py
	docker build -t albert-server:local . || echo "docker build skipped"

ci: validate lint test security

trivy:
	trivy fs . --severity HIGH,CRITICAL
