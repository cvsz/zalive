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

setup format lint test build security:
	@echo 'This is a template placeholder: implement this target for your actual project; do not treat it as a passing check.' >&2
	@exit 2

lint:
	ruff check .

test:
	python -m pytest -q --ignore=tests/test_bootstrap.py

security:
	bandit -r . --exclude ./venv -q

build:
	docker compose config > /dev/null
	python3 -m py_compile albert_server.py

ci: validate lint test security

trivy:
	trivy fs . --severity HIGH,CRITICAL
