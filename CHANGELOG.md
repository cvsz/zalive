# Changelog — albert_server

All notable changes to `albert_server` (Local Albert for iPhone XR) documented per Keep a Changelog. Version `1.1-fixed` → `v0.1.0`.

## [v0.1.0] - 2026-09-28

### Added
- Any-iPhone curated `XR + 12/13/14/15` (`iPhone11,8/12,1/13,2/14,5/15,2`, `A12/A13/A14/A15/A16`) with dynamic `activations.producttype` (fallback XR `MT1A2TH/A 00008020-001224C81178002E`), dashboard `Any iPhone`.
- Firmware pages `GET /firmware` (dark table Version|Build|Release|Size|Signed `✓`/`✗`|Local `✅`|Download `⬇` Apple `url`) + `GET /api/devices` (5 curated) + `GET /api/firmwares?productType=X` live `https://api.ipsw.me/v4/device/{ProductType}` cached 1h `logs/firmware_cache.json 0600` + local `*.ipsw` overlay.
- Dashboard realtime `GET /dashboard` 2s poll `/api/status` (health/ready/fairplay 0600, metrics `activations/wal`, iPhone redacted `0000...002E`, USB `05ac`, IPSW `b30474b…`) + `/api/activations` `/api/logs` + `GET /` endpoints list.
- Production hardening: persisted `certs/fairplay.key/crt 0600` (was ephemeral), `gunicorn 2×4 30s`, `MAX_CONTENT_LENGTH 512K 413`, per-IP `100/min 429` (prune cap 1000), UDID/IMEI validation `400`, `X-Request-ID` UUID echo, JSON logs (`python-json-logger`), `{{prometheus}}` histogram `albert_request_latency_seconds`, SQLite WAL `logs/activations.db` `10k/30d` retention + `wal_checkpoint`, UDID redaction `...2E`.
- Security: `0600` keys, `SECURITY.md` `ALBERT_ACCEPT_RISK=1` gate, `Bandit` `B303/B324 nosec` SHA1 ARS Apple-spec, `.gitignore` `*.ipsw !*.sha256`, `0600 .env` real `ALBERT_ACCEPT_RISK=1`.
- Client `activate_device.py` `3` retries exponential `1s/2s/4s` `413/429/5xx`, `X-Request-ID`, `--json`, validation.
- Docker `USER app read_only cap_drop ALL no-new-privileges 0.5G/1CPU` + `HEALTHCHECK curl /health`, `systemd` `albert-server.service` + `launchd` roadmap, `gunicorn_conf.py` access log with `X-Request-ID`.
- Tests `18 passed` (`12 albert` + `6 firmware any-iPhone`), `ruff All checks passed`, `bandit 0`, `docker compose config ok`, `GPG EDDSA CD57FEA` `5e04f52` (template merge `edb461b` `d9a4e76`), `zalive` `https://github.com/cvsz/zalive` `albert-server` + `main`.

### Changed
- `zTemplate` baseline: `README` `Local Albert`, `ABOUT` builder, `CODEOWNERS @cvsz` kept; `Makefile` placeholder noted, `.env.example` still `APP_ENV 3000` (stale, next: Albert keys) — `real .env` is `18090`.
- Ports `8080` conflict → `18090`/`18443`/`8081`/`8082` (host+docker).

### Fixed
- `create_activation_record` `b""` crash → placeholder cert, `activation-info` base64 `pls` fix, `TSS` not intercepting `gs.apple.com` (proxy only `albert.apple.com`), producttype fallback not `DeviceClass "iPhone"`.

## [Unreleased]
- Redis distributed rate limit + per-UDID, `Postgres` option, Grafana + `albert_up==0` alert, `mTLS` proxy→Albert, `cosign` attestations.

