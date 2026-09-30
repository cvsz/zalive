# Contributing to albert_server

Thank you for contributing. This project follows the template contract in [AGENTS.md](AGENTS.md).

## Quick Start

```bash
# Fork → clone → branch
git clone https://github.com/<your-fork>/albert_server
cd albert_server
git checkout -b my-change

# Setup
cp .env.example .env
# edit .env (ALBERT_ACCEPT_RISK=1, tokens)

# Run tests
pytest -q

# Lint & security
ruff check .
bandit -r . --exclude ./venv
```

## Pull Request Requirements

Every PR must include:

1. **Scope** — What changes, why, and what problem it solves
2. **Tests** — New tests for new behavior; existing tests pass
3. **Security Impact** — Does this change attack surface, auth, crypto, or secrets?
4. **Compatibility** — Breaking changes? Migration path?
5. **Documentation** — README, CHANGELOG, docstrings updated?
6. **Deployment** — Config changes? Dockerfile? Systemd?

## Commit Messages

```
<type>(<scope>): <subject>

<body>

<footer>
```

Types: `feat`, `fix`, `docs`, `refactor`, `test`, `chore`, `security`

Example:
```
fix(rate-limit): add warning on Redis fallback

Redis rate limit failures now log WARNING instead of silently
falling back to in-memory. Prevents silent degradation in
multi-worker deployments.

Closes #42
```

## Code Standards

- **Python**: 3.13+, type hints where practical
- **Lint**: `ruff check .` (config in `pyproject.toml`)
- **Security**: `bandit -r . --exclude ./venv` — no new HIGH/MEDIUM
- **Tests**: `pytest -q` — 100% pass required
- **Docker**: `docker compose config && docker compose build` — must succeed

## Security

- **Never commit secrets** — use `.env.example` placeholders
- **Report vulnerabilities** via GitHub Security Advisory (not public issues)
- **Crypto changes** require explicit review — FairPlay, mTLS, signatures
- **Dependencies** pinned with hashes in `requirements.txt`

## Release Process

1. Update `CHANGELOG.md` (Keep a Changelog format)
2. Tag: `git tag -s vX.Y.Z -m "Release vX.Y.Z"`
3. Push tag: `git push origin vX.Y.Z`
4. GitHub Actions builds and publishes

## Questions?

- Check [SECURITY.md](SECURITY.md) for threat model
- Check [AGENTS.md](AGENTS.md) for template contract
- Open a GitHub Discussion for design questions