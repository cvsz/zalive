.PHONY: test lint bandit compose-check

test:
	PYTHONPATH=. pytest -q

lint:
	ruff check .

bandit:
	bandit -r . --exclude ./venv

compose-check:
	docker compose config -q
