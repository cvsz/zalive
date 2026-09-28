# Roadmap — albert_server

Derived from `zTemplate` foundation, now `albert_server` product `v0.1.0 2026-09-28` (`5e04f52`).

## Foundation — done
- [x] Repository docs, security, issue/PR templates, CI `ruff/bandit/pytest` 18, Dependabot, release workflow, `Dockerfile` `USER app` `HEALTHCHECK`, `architecture.md` (133 lines) + `docs/superpowers/specs` curated.

## Reusable first-project startup — done (not re-bootstrapped)
- [x] `zTemplate` `5e04f52` merged via `allow-unrelated-histories` (kept `README` Local Albert, not generic).
- [x] `docs/profiles.md` curated any-iPhone, `docs/startup.md` `18090` quick start, `IMPLEMENTATION-CHECKLIST.md` updated (GPG 18 tests).
- [ ] `Makefile` placeholder still → next: real `make test/lint/security/build/ci`.
- [ ] `.env.example` stale (`APP_ENV 3000`) → next: `ALBERT_HTTP_PORT/FAIRPLAY...`.

## Product backlog (P2) — next
- [x] Any-iPhone curated `XR+12/13/14/15` + `albert_server` dynamic `producttype` + `dashboard Any iPhone`.
- [x] Firmware pages `/firmware` live `ipsw.me` cache 1h + local overlay.
- [ ] Language adapters (python `3.14-slim` `3.14.4` already validated; add `3.11/3.12` matrix optional).
- [ ] E2E fixture: `idevicerestore -e -y iPhone11,8_18.7.10_22H374_Restore.ipsw` needs USB `05ac` (VM passthrough) — blocked, `Unable to discover device mode` preserved.
- [ ] Distributed `Redis` `100/min` per-IP + per-UDID, `Postgres` option, `OTEL` traces, `mTLS`, `trivy fs` `SBOM`, `cosign`.

