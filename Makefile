SHELL := /bin/sh

.PHONY: help validate-template setup format lint test build security ci

help:
	@printf '%s\n' 'Template: validate-template' 'Project (configure before use): setup format lint test build security ci' 'Bootstrap: python3 scripts/bootstrap.py --help'

validate-template:
	python3 -m unittest discover -s tests -v

setup format lint test build security:
	@echo 'This is a template placeholder: implement this target for your actual project; do not treat it as a passing check.' >&2
	@exit 2

ci: validate-template lint test build security
