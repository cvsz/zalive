# Changelog — albert_server

All notable changes to `albert_server` (Local Albert for iPhone 5→15 Pro) documented per Keep a Changelog.

## [Unreleased] - 2026-09-30

### Fixed
- `activate_device.py` broken against pymobiledevice3 v11: `get_device_info` read `MuxDevice.udid` but v11 exposes `.serial`, and `LockdownClient` became an abstract class. Now resolves the UDID across all attribute names and uses `await create_using_usbmux()`. `--info` works again.

### Security
- `.gitignore` hardening. Added `*.p12`/`*.pfx`/`*.jks`/`*.keystore` (PKCS#12 embeds a private key in a single file — the previous rules covered only `*.pem`/`*.key`/`*.crt`/`*.csr`), `.mitmproxy/`/`mitmproxy-ca*` (interception CA private key), Apple firmware components `*.im4p`/`*.im4m`/`*.trustcache`/`*.mtree`/`*.root_hash`/`*.aea`/`*.dmg.*`/`*.iBEC`/`*.iBSS` (previously only matched under `firmware/` at the repo root), `*.shsh` (filenames embed the device ECID), `*.db`/`*.sqlite*` (activation records hold UDID/IMEI/serial), `*.srl`, and the RE scratch files `kernel.decompressed`/`iboot.decompressed`/`*.sweep.json`.
- `logs/restore/` no longer blanket-un-ignores its contents. The old `!logs/restore/*` re-opened the whole folder and relied on a later `.log`-specific rule to close it, so any new file type would have been committed. Now the folder is re-opened and immediately re-closed, with only `README.md` allowed through.
- Device identifiers (UDID/IMEI/serial/ECID) redacted from `docs/re/` and the RE scripts.

### Added
- `docs/re/` — reverse-engineering write-ups: activation protocol (4 hops, trust anchor), iOS 18.7.10 IPSW structure (76 components, the two BuildIdentities explained as erase/update ramdisks, Image4 DER framing), and a work report.
- `scripts/` — read-only RE tooling: `parse_im4.py`, `extract_kernel.py`, `analyze_kernel.py`, `sweep_kernel.py`, plus activation helpers `try_activate.py`, `activate_real_apple.py`, `diagnose_activation_reject.py`. None store credentials.
- `docs/ai/`, `skills/`, `plugins.d/`, `components.d/`, `ecc-install.json`, `CLAUDE.md`, `OPENCODE.md`, `docs/repository-rollout.md` — imported from `cvsz/ztemplate` `main` (`4f40f89`). Existing Local Albert files were left untouched.

### Changed
- Repository language contract is now Thai for explanations/documentation/comments with English for code, configuration, and technical terms.

### Known issues
- Activation against real Apple is blocked server-side by the device owner's account state (`Apple Account disabled`). The local server cannot satisfy the FairPlay DRM handshake: the device verifies `HandshakeResponseMessage` against Apple's public key and the signing key never appears on the wire. The previous placeholder response shares only one of five key names with Apple's real response, and three of its keys do not exist in Apple's protocol at all.
- Erase restore succeeds from the physical host but fails from inside the VMware guest — USB passthrough drops the device across the Recovery to Restore handoff.

## [v0.2.0] - 2026-09-29

### Security
- **P0**: `/api/status` public endpoint now uses allowlist payload (health/ready/version only); device/activations/env/fairplay/rate/usb require admin token
- **P0**: mitmproxy web UI fail-closed password (`${MITMPROXY_WEB_PASSWORD:?must be set}`); no default/fallback
- **P0**: `ALBERT_ACCEPT_RISK=0` in `.env.example`; operator must explicitly opt-in
- Docker supply-chain: `--require-hashes` enforced in multi-stage build
- Container bind `0.0.0.0`; host publish controlled by `ALBERT_BIND_ADDRESS` (default `127.0.0.1`)
- Activations table: `UNIQUE(udid) ON CONFLICT REPLACE` for dedup
- IPSW scan: removed parent-dir glob, added cwd check

### Added
- Compose E2E CI job: `docker compose up --wait`, health/ready auth gates, restart persistence, `down -v`
- Public allowlist payload function `_build_public_status_payload()`
- Dashboard restore progress live UI (idevicerestore)
- `ALBERT_BIND_ADDRESS` env var for secure host port binding

### Changed
- Ports: Albert `18090`/`18443`, mitmproxy `28080`/`28081` (was `8081`/`8082`)
- Secure-by-default host binding via `ALBERT_BIND_ADDRESS` separate from container `ALBERT_HOST=0.0.0.0`
- Dockerfile: restored `tini`, selective `COPY`, OCI labels, `--require-hashes`
- Tests: 37 passed (was 36), updated for privacy fix
- CI: Bandit B105 fixed (no hardcoded tokens), docker compose config timeout 15s

### Fixed
- Docker build regression (lzfse headers via `python3-dev` in builder)
- mitmproxy web UI auth check in CI (verify port open + HTTP != 200)
- `.dockerignore` includes `scripts/`, `logs/.gitkeep`, `logs/restore/README.md`
- CI secret leak: removed `cat .env` from compose-e2e

## [v0.1.0] - 2026-09-28

### Added
- Any-iPhone curated `XR + 12/13/14/15` (`iPhone11,8/12,1/13,2/14,5/15,2`, `A12/A13/A14/A15/A16`) with dynamic `activations.producttype` (fallback XR `MT1A2TH/A` redacted), dashboard `Any iPhone`.
- Firmware pages `GET /firmware` (dark table Version|Build|Release|Size|Signed `✓`/`✗`|Local `✅`|Download `⬇` Apple `url`) + `GET /api/devices` (13 curated) + `GET /api/firmwares?productType=X` live `https://api.ipsw.me/v4/device/{ProductType}` cached 1h `logs/firmware_cache.json 0600` + local `*.ipsw` overlay.
- Dashboard realtime `GET /dashboard` 2s poll `/api/status` (health/ready/fairplay 0600, metrics `activations/wal`, iPhone redacted `0000...002E`, USB `05ac`, IPSW `b30474b…`) + `/api/activations` `/api/logs` + `GET /` endpoints list.
- Production hardening: persisted `certs/fairplay.key/crt 0600` (was ephemeral), `gunicorn 2×4 30s`, `MAX_CONTENT_LENGTH 512K 413`, per-IP `100/min 429` (prune cap 1000), UDID/IMEI validation `400`, `X-Request-ID` UUID echo, JSON logs (`python-json-logger`), Prometheus histogram `albert_request_latency_seconds`, SQLite WAL `logs/activations.db` `10k/30d` retention + `wal_checkpoint`, UDID redaction `...2E`.
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