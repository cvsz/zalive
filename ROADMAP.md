# Roadmap — albert_server

Derived from `zTemplate` foundation, now `albert_server` product `v0.1.0 2026-09-28` (`5e04f52`).

## Foundation — done
- [x] Repository docs, security, issue/PR templates, CI `ruff/bandit/pytest` 18, Dependabot, release workflow, `Dockerfile` `USER app` `HEALTHCHECK`, `architecture.md` (133 lines) + `docs/superpowers/specs` curated.

## Reusable first-project startup — done (not re-bootstrapped)
- [x] `zTemplate` `5e04f52` merged via `allow-unrelated-histories` (kept `README` Local Albert, not generic).
- [x] `docs/profiles.md` curated any-iPhone, `docs/startup.md` `18090` quick start, `IMPLEMENTATION-CHECKLIST.md` updated (GPG 118 tests).
- [x] `Makefile` replaced with real targets — `test`, `test-verbose`, `lint`, `security`, `check` (lint+security+tests), `validate`, `docker-build`, `docker-up`, `docker-down`, `logs`, `run`, `stop`, `rotate-fairplay`, `clean`; `make help` self-documents them.
- [x] `.env.example` aligned with runtime — `ALBERT_HTTP_PORT=18090`, `ALBERT_BIND_ADDRESS`, `FAIRPLAY_KEY_PATH`, `FAIRPLAY_CERT_PATH`, `ALBERT_ACCEPT_RISK=0`, `MITMPROXY_WEB_PASSWORD`. Stale `APP_ENV 3000` removed.

## Product backlog (P2) — next
- [x] Any-iPhone curated `XR+12/13/14/15` + `albert_server` dynamic `producttype` + `dashboard Any iPhone`.
- [x] Firmware pages `/firmware` live `ipsw.me` cache 1h + local overlay.
- [ ] Language/runtime compatibility matrix: `python:3.13-slim` remains the pinned container runtime and CI currently tests Python 3.13 only; add 3.11/3.12 coverage only if product support policy requires it. No open Dependabot PR is present at this refresh.
- [x] E2E restore verified on hardware: `idevicerestore -e -y iPhone11,8_18.7.10_22H374_Restore.ipsw` completed with `Status: Restore Finished` on iPhone11,8 / 18.7.10 (`22H374`). Root cause of the earlier `Unable to discover device mode` failures was VMware USB passthrough dropping the device between Recovery and Restore, not the tool or the IPSW. Details: `docs/re/WORK-REPORT.md` §2.
- [ ] Activation against real Apple still blocked on the device owner's account state (`Apple Account disabled` server-side). The FairPlay DRM handshake cannot be satisfied by a local server — the signing key is private to Apple. Details: `docs/re/ACTIVATION-PROTOCOL.md`.
- [ ] Remaining optional production features: PostgreSQL backend, OTEL traces, Trivy/SBOM and cosign attestations. Redis-backed rate limiting and mTLS controls already exist in the current configuration/code path and should not be listed as wholly unimplemented.

