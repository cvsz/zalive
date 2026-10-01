# Architecture — albert_server (Local Albert for iPhone XR + any iPhone)

## Overview

Local emulator of `albert.apple.com` for iOS restore/activation testing (primary `iPhone11,8` iPhone XR, curated `iPhone12,1`/`13,2`/`14,5`/`15,2`).
All activation is **local**; TSS (`gs.apple.com`) passes through to Apple unless a local TSS is explicitly enabled.
Production entry is `gunicorn` (`gunicorn_conf.py`); dev fallback is `python albert_server.py`. Port fixed `18090`.

## System Context

```
                         ┌─────────────────────────────────┐
                         │          iOS Device             │
                         │  Recovery / DFU / Hello screen  │
                         └──────────┬──────────────────────┘
                                    │ USB (usbmuxd, iproxy)
                                    │ Wi-Fi (HTTP proxy)
                                    ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                        Host / Container Host                            │
│                                                                         │
│   Device Wi-Fi proxy ─────►  mitmproxy (mitmweb)                        │
│                            │  127.0.0.1:28081 proxy                      │
│                            │  127.0.0.1:28080 web UI (auth)             │
│                            │  script: firmware_restore_proxy.py         │
│                            │  ALBERT_HOSTS=[albert.apple.com]          │
│                            │  TSS_HOSTS=[] (pass-through)              │
│                            │         │                                   │
│                            │         │ X-Forwarded-Host: albert.apple.com│
│                            │         │ scheme=http (LOCAL_ALBERT_SCHEME)│
│                            │         ▼                                   │
│                            │  ┌──────────────────────────┐               │
│                            │  │ Local Albert (Flask)     │               │
│                            │  │ gunicorn -w2 -k gthread  │               │
│                            │  │ --threads 4 -b 0.0.0.0:18090│             │
│                            │  │ albert_server:app        │               │
│                            │  │ gunicorn_conf.py         │               │
│                            │  │ PORT: 18090 (HTTP)       │               │
│                            │  │ 18443 HTTPS dev only     │               │
│                            │  └──────────┬───────────────┘               │
│                            │             │                                  │
│                            │             ├─► FairPlay key  certs/fairplay.key (0600) │
│                            │             │   certs/fairplay.crt (0600)   │
│                            │             │   Generated once, loaded on boot │
│                            │             ├─► SQLite logs/activations.db (WAL)│
│                            │             │   logs/activations.jsonl (legacy)│
│                            │             ├─► Prometheus /metrics albert_up  │
│                            │             ├─► JSON logs (python-json-logger) │
│                            │             │   X-Request-ID, redacted UDID  │
│                            │             └─► /health (liveness) 200       │
│                            │                 /ready  (key loaded) 200/503 │
│                            └──────────────────────────────────────────────│
│                                     │                                     │
│                                     │ TSS / appldnld / mesu / osrecovery │
│                                     │ NOT intercepted — pass-through      │
│                                     ▼                                     │
│                            ┌─────────────────────────┐                    │
│                            │ Apple Servers           │                    │
│                            │ albert.apple.com [INT]  │                    │
│                            │ gs.apple.com [PASS]     │                    │
│                            │ osrecovery/mesu [PASS]  │                    │
│                            └─────────────────────────┘                    │
│                                                                         │
│   Docker (docker-compose.yml)                                           │
│   ┌─────────────────────┐   ┌─────────────────────┐                     │
│   │ albert-server       │   │ mitmproxy            │                     │
│   │ build: . (3.14-slim)│──▶│ image: 12.2.3        │                     │
│   │ USER app, readOnly  │   │ 127.0.0.1:28080/28081  │                     │
│   │ ports 18090,18443   │   │ web_password=$MITMP..│                     │
│   │ healthcheck /health │   │ depends_on healthy   │                     │
│   └─────────────────────┘   └─────────────────────┘                     │
│   network: albert-network (bridge)   volumes: certs:ro, logs           │
└─────────────────────────────────────────────────────────────────────────┘

IPSW: iPhone11,8_18.7.10_22H374_Restore.ipsw (8.1 GB) — NOT in repo, stored
externally; scripts/sha256_manifest.sh produces *.ipsw.sha256 + ipsw.sha256.
.gitignore ensures *.ipsw ignored but *.sha256 kept (!*.sha256).
Upstream: api.ipsw.me/v4/device/{productType} live cache 1h (logs/firmware_cache.json, TTL 3600, stale fallback).
```

Flow: `iOS device` → `mitmproxy :28081` (intercepts only `albert.apple.com`) → `Albert :18090` (`Flask` + `gunicorn` 2 workers ×4 threads) → `SQLite WAL logs/activations.db` + `fairplay.key 0600` + `ipsw.me live cache 1h` (curated `CURATED_DEVICES` 13, `FIRMWARE_CACHE`, `FIRMWARE_TTL=3600`). `FairPlay` key/cert `0600` (`certs/fairplay.key` RSA 2048, CA `Apple iPhone Device CA`, 5y SHA256) persisted once. `IPSW` 8.1G external, `local_overlay` scan `*.ipsw`.

## Components and Responsibilities

| Component | File | Role | Port / bind |
|-----------|------|------|-------------|
| Albert server | `albert_server.py` | Flask app: `/deviceservices/drmHandshake`, `/deviceActivation`, `/WebObjects/ALUnbrick…`, `/health`, `/ready`, `/metrics`, `/certifyMe`, `/activity`, `/phoneHome`, `/dashboard`, `/firmware`, `/api/*` | `ALBERT_HOST:ALBERT_HTTP_PORT` (`127.0.0.1:18090` default, `0.0.0.0:18090` in container) |
| Gunicorn | `gunicorn_conf.py` | Prod WSGI: `gthread`, `workers=2 threads=4`, `timeout 30`, `graceful 10`, `keepalive 5`, `limit_request_*`, JSON access log with `X-Request-ID` | `bind = $ALBERT_HOST:$ALBERT_HTTP_PORT` |
| Proxy | `firmware_restore_proxy.py` | mitmproxy addon: only `albert.apple.com` → local; `gs.apple.com` pass-through; adds `X-Forwarded-*` | `LOCAL_ALBERT_HOST:LOCAL_ALBERT_PORT` → `127.0.0.1:18090` (or `albert-server:18090`) |
| Activation client | `activate_device.py` | Direct `POST` to Albert without proxy (alternative to Wi-Fi proxy), `--albert-url http://127.0.0.1:18090`, retries `10s`×`3` exponential, `X-Request-ID` | `DEFAULT_ALBERT_URL 127.0.0.1:8080` (the constant in `activate_device.py:182` is still 8080; the server moved to 18090, so pass `--albert-url http://127.0.0.1:18090`) |
| IPSW | `iPhone11,8_18.7.10_22H374_Restore.ipsw` (8.1 GB) | External restore image, `scripts/sha256_manifest.sh` → `*.sha256`/`ipsw.sha256`, `.gitignore *.ipsw` | filesystem + `api.ipsw.me` |
| Firmware service | `albert_server.py:_fetch_ipsw` | `ipsw.me` live fetch with `logs/firmware_cache.json` TTL `3600`, curated `CURATED_SET`, stale fallback, allow any `iPhone\d+,\d+` | `IPSW_API https://api.ipsw.me/v4/device/{productType}` |
| Compose | `docker-compose.yml` | Three-service stack, `read_only`, `cap_drop ALL`, `no-new-priv`, `healthcheck /health` | `18090`, `18443`, `28080`, `28081` (mitmproxy bound `127.0.0.1`) |
| Dockerfile | `Dockerfile` | `python:3.14-slim`, `tini`, `useradd app`, `USER app`, `HEALTHCHECK` | `EXPOSE 18090 18443` |
| systemd | `systemd/albert-server.service` | `User=cvsz`, `WorkingDirectory`, `ExecStart gunicorn`, `Restart=on-failure`, `PrivateTmp`, `NoNewPrivileges` | `0.0.0.0:18090` via `gunicorn_conf.py` |

### Activation request flow (session mode)

1. **drmHandshake** — device sends `HandshakeRequestMessage` (+ optional CSR); Albert returns a
   research-stub response. Apple's real response carries only four keys (`serverKP`, `FDRBlob`,
   `SUInfo`, `HandshakeResponseMessage`); three of the keys this server returns do not exist in
   Apple's protocol. The device verifies the signature on `HandshakeResponseMessage`, rejects the
   stub, and aborts at `CreateTunnel1ActivationInfoRequest` with `Invalid session response` before
   `deviceActivation` is ever called. **No local response can pass this check** — the FairPlay
   signing key is private to Apple. See `docs/re/ACTIVATION-PROTOCOL.md`.
2. **deviceActivation** — device sends `activation-info` (base64 plist, form `activation-info`, or
   `application/x-apple-plist`). Albert validates `IMEI`/`UDID`/`Serial`, generates or reuses a
   `DeviceCertificate` from the CSR, signs `AccountToken` with the FairPlay key (Apple-spec `ARS`
   header), and returns an `activation-record` plist. Persisted to `logs/activations.db`.
3. **TSS** (`gs.apple.com/TSS/controller?action=2`) — not intercepted; reaches Apple for SHSH.
4. **Health** — `GET /health` always `200`; `GET /ready` is `200` iff the FairPlay chain is
   loaded, else `503`; `GET /metrics` emits `albert_up` and activation counters.

## Data/Storage Model

- **Keys**: `certs/fairplay.key`/`fairplay.crt` (`0600`, PEM, RSA 2048, CA `Apple iPhone Device CA`, 5y `SHA256`). Generated once in `AlbertServer.__init__`; `chmod 600` enforced. `certs/server.crt/key` for dev HTTPS only (`CN=albert.local`, 365d). `FIRMWARE_CACHE` also `0600`.
- **Activations**: SQLite `logs/activations.db` (`WAL`, table `activations(id, udid, serial, created_at, record, producttype)`), host volume `logs:/app/logs` in compose. `logs/` is `.gitignore`'d; DB via `DB_PATH`/`ALBERT_DATABASE_URL` (`sqlite:///` default, `postgres://` optional via `psycopg2`). `logs/activations.db-wal/shm` WAL artifacts.
- **Firmware cache**: `logs/firmware_cache.json` (`0600`, `FIRMWARE_TTL=3600` 1h, per-`productType` `{fetchedAt, data{firmwares[]}}`, cached/stale flags, local overlay via `_scan_local_ipsw`).
- **Logs**: `python-json-logger` JSON (`timestamp`, `level`, `name`, `message`, `request_id`, `remote_addr`) or plain fallback; `X-Request-ID` middleware (`uuid4`); `UDID` suffix-only (`…2E` via `_redact_udid`); `albert.log`, `mitmproxy.log`, `logs/` all gitignored.
- **IPSW**: `iPhone11,8_18.7.10_22H374_Restore.ipsw` (8.1 GB) external; `scripts/sha256_manifest.sh` emits `*.ipsw.sha256` + `ipsw.sha256` (tracked `644`), `*.ipsw` ignored, aggregate manifest `ipsw.sha256`.

## External Integrations

- `albert.apple.com` — intercepted (only host in `ALBERT_HOSTS`), rewritten to local via `X-Forwarded-Host/Proto/By`.
- `gs.apple.com` (`TSS/controller?action=2`), `osrecovery.apple.com`, `appldnld.apple.com`, `mesu.apple.com` — **not** intercepted; pass-through to Apple for SHSH/firmware (proxy logs keyword but does not redirect; `TSS_HOSTS=[]` empty).
- `api.ipsw.me` — live firmware metadata (`GET /v4/device/{productType}`, `User-Agent Albert-firmware/1.0`, `timeout 8s`, cache 1h, stale fallback on error with `warning`).
- `Apple Servers` — restore path `TSS/appldnld/mesu/osrecovery` reaches Apple unchanged.

## Authentication and Authorization

- No Apple `Authorization` reused; local Albert is unauthenticated LAN service (trusted proxy network `albert-network` bridge, `mitmproxy` bound `127.0.0.1`).
- `mitmproxy` web UI `28080` auth via `MITMPROXY_WEB_PASSWORD` env (`web_password=$MITMPROXY_WEB_PASSWORD`).
- Device identity validated synthetically: `IMEI` 15 digits (`_validate_imei`), `UDID` 40 hex or `00008020-<16 hex>` (`_validate_udid`), `Serial` alnum (`_validate_serial`); activation client mirrors same `re` checks before POST.

## Trust Boundaries

| Boundary | Control | Detail |
|----------|---------|--------|
| `X-Request-ID` | `before_request_hardening` + `after_request_add_id` | UUID `uuid4` per request (`request.headers X-Request-ID` or generated), stored `g.request_id`, echoed `Response.headers X-Request-ID`, JSON log `request_id`, 429/413 JSON `request_id`, gunicorn `access_log_format ... %({X-Request-ID}i)s` |
| Redacted UDID | `_redact_udid` + logs/dashboard | Only suffix shown (`…2E` / `slice(0,4)+...+slice(-4)`), full UDID SQLite but never in JSON logs/metrics/dashboard table, `RequestIdFilter` includes `remote_addr` not raw UDID |
| Rate 100/min | `_check_rate_limit` / `_rate_limit_store` | In-memory per-IP `100/min` window `60s`, `Max 1000 IPs` cap (evict oldest 100), applied to `deviceActivation`/`drmHandshake` only (not health), `429 rate limit exceeded` + `Retry-After` handling in `activate_device.py` exponential backoff `1s,2s,4s` |
| MAX 512K | `app.config MAX_CONTENT_LENGTH` + gunicorn limits | Env `ALBERT_MAX_CONTENT_LENGTH` default `512*1024`, `RequestEntityTooLarge` → `413 payload too large` with `limit`+`request_id`, gunicorn `limit_request_line 4096`, `limit_request_fields 50`, `limit_request_field_size 8190` |
| `ALBERT_ACCEPT_RISK` gate | `start.sh:check_risk_gate` + systemd/env | `ALBERT_ACCEPT_RISK=1` required to start (`prod`/`dev`); failure `exit 2` with `SECURITY.md/NOTICE` message; checks `.env` `^ALBERT_ACCEPT_RISK=1`; lab override `--allow-no-risk`; `.env.example` documents gate |

## Deployment Topology

| Mode | Command | Server | TLS | Risk gate |
|------|---------|--------|-----|-----------|
| prod (default) | `docker compose up -d` | `gunicorn -c gunicorn_conf.py albert_server:app` | `mitmproxy` terminates TLS; Albert `http` | `ALBERT_ACCEPT_RISK=1` required |
| dev | `python albert_server.py --host 0.0.0.0 --port 18090` | Flask dev server | Optional `certs/server.crt/key` on `18443` | Same gate |
| docker | `docker compose up -d --build` | `gunicorn` in container | Same as prod | Env `ALBERT_ACCEPT_RISK=1` |

- **Host**: `0.0.0.0:18090` (`ALBERT_HOST` env, `gunicorn_conf.py:bind`), `18443` HTTPS dev only (`certs/server.crt/key`); container `albert-server:18090` vs `127.0.0.1:18090` vs `LOCAL_ALBERT_HOST` toggle (docker `albert-server`, host `127.0.0.1`).
- **Docker Compose** (`docker-compose.yml`): three services `albert-server` (`build: . python:3.14-slim`, `USER app`, `read_only:true` `tmpfs /tmp`, `cap_drop ALL` `cap_add CHOWN/SETUID/SETGID`, `no-new-privileges`, `deploy resources limits cpus 1 memory 512M`, `volumes certs:ro logs`, `env_file .env`, `healthcheck curl /health`) + `mitmproxy` (`image 12.2.3`, `mitmweb -s firmware_restore_proxy.py --set block_global=false --web-host 0.0.0.0 --web-port 28080 --set web_password=$MITMPROXY_WEB_PASSWORD`, ports `127.0.0.1:28080/28081`, `depends_on healthy`, `network albert-network bridge`).
- **systemd** (`systemd/albert-server.service`): `[Unit] After=network.target`, `[Service] User=cvsz WorkingDirectory=/home/cvsz/albert_server ExecStart=/home/cvsz/albert_server/venv/bin/gunicorn -c gunicorn_conf.py albert_server:app Restart=on-failure RestartSec=5 EnvironmentFile=-.env PrivateTmp NoNewPrivileges`.
- **Scaling**: `gunicorn` `workers=2 threads=4` (`gthread`), `timeout 30`, `graceful 10`, `keepalive 5`; stateless Flask + SQLite WAL (concurrent reads), rate limiter in-memory per worker (non-distributed).

## Observability

- `GET /health` — liveness `200 {"status":"ok","server":"albert-local","version":"1.1-fixed"}` always.
- `GET /ready` — readiness `200 ready` iff `FAIRPLAY_CERT_CHAIN` + `fairplay_private_key` loaded else `503 not-ready`.
- `GET /metrics` — Prometheus exposition via `prometheus_client` (`albert_up` gauge, `albert_activation_total`/`albert_activation_failures_total` counters, `generate_latest` + `CONTENT_TYPE_LATEST`) or stub fallback counting SQLite rows.
- **Dashboard** `GET /dashboard` — realtime 2s poll HTML (`DASHBOARD_HTML`): server port/env, FairPlay `0600` loaded/persisted `notAfter/serial/subject`, metrics `activations/failures/up WAL`, iPhone identity (`ProductType/ModelNumber/Serial/UDID redacted/EID/IMEI/Storage` dynamic from last activation `CURATED_DEVICES`), USB (`lsusb 05ac`, `idevice_id -l`, `idevicerestore --no-action`), IPSW (`iPhone11,8_18.7.10_22H374_Restore.ipsw` 8.1GB `sha256` `productVersion 18.7.10 build 22H374` variants), recent activations SQLite WAL table 5 rows, rate `IPs/window 60s max100`, logs tail `60` lines. APIs `GET /api/status` (aggregate `health/ready/fairplay/metrics/device/usb/ipsw/activations/rate/env/db/now`), `GET /api/logs?lines=60` (tail `/tmp/albert.log`/`albert.log`/`logs/albert.log`), `GET /api/activations`.
- **Firmware** `GET /firmware` — curated `XR+12/13/14/15` (`FIRMWARE_HTML`): `select productType`, search `version/build`, banner `cached 1h`/`stale`, table `Version/Build/Released/Size/Signed/Local/Download`. APIs `GET /api/devices` (`CURATED_DEVICES` 5), `GET /api/firmwares?productType=iPhone11,8` (`PRODUCT_RE ^iPhone\d+,\d+$`, `firmwares[] local[] cached fetchedAt stale warning`, `_fetch_ipsw` 1h cache + local overlay `_scan_local_ipsw`, `502 upstream unavailable retryAfter 60`).

## Availability and Recovery

- `health`/`ready` separate liveness vs key-loaded readiness; compose `healthcheck` + `depends_on healthy` gates mitmproxy; systemd `Restart=on-failure`.
- SQLite `WAL` + `timeout 30` per connection; `_init_db` idempotent `CREATE TABLE IF NOT EXISTS` + `PRAGMA journal_mode=WAL`, column migration `producttype`, Postgres fallback `ALBERT_DATABASE_URL` (`psycopg2` else sqlite).
- `FIRMWARE_CACHE` stale fallback: on `requests.get` exception returns last cached `stale True` with `warning`.
- `activate_device.py` retries `MAX_RETRIES=3` exponential `BACKOFF_FACTOR 1.0` handling `413/429/5xx/Timeout/ConnectionError` with `Retry-After`.
- Rotation: `rm certs/fairplay.key certs/fairplay.crt && ./start.sh restart` (backup `certs/` before, `ALBERT_ACCEPT_RISK` gate, `chmod 600` enforced on regenerate).
- Failure modes: `18090` busy `ss -tln` hint (migrated from `8080` nginx/fastapi conflict); `ALBERT_ACCEPT_RISK !=1` abort `exit 2`; `413` plist >512KB; `503 /ready` missing key `ls -l certs/`; `block_global=false` fixed prevents global exposure; `Unable to discover device mode` → USB passthrough (`VM Removable Devices Apple 05ac`).

## Security Considerations

- **SHA1 ARS nosec (Apple-spec)**: `albert_server.py:AlbertServer.sign_activation_info` `private_key.sign(..., hashes.SHA1())  # nosec B303/B324` + `deviceActivation` `hashlib.sha1(response_plist)  # nosec B303/B324` for `ARS` header `base64(sha1(plist))`; Apple activation requires SHA1, not for general hashing — annotated `nosec` + comment `Apple-spec — Apple requires SHA1 for ARS header`. `fallback_key`/`DeviceCertificate` signed `SHA256`.
- **mTLS toggle**: TLS terminated at `mitmproxy` (`http://mitm.it` CA installed on device, `LOCAL_ALBERT_SCHEME=http` behind TLS, `LOCAL_ALBERT_SCHEME=https` optional when `certs/server.crt` present dev `18443`); proxy→Albert `http` default, `https` toggle via `LOCAL_ALBERT_SCHEME`/`ALBERT_MTLS` env (future `client cert` via gunicorn `certfile/keyfile/ca_certs` if `mTLS=true` — currently `off`, document toggle in `SECURITY.md`).
- **Keys 0600**: `certs/fairplay.key`/`fairplay.crt`/`server.key` `0600` (`chmod 0600` in code + `setup.sh`), `.gitignore` `*.key`/`*.pem`/`logs/`/`*.log`/`*.ipsw`.
- **Risk gate**: `ALBERT_ACCEPT_RISK=1` env required (`start.sh` + `SECURITY.md` threat model, `NOTICE` Apple ToS disclaimer `for testing owned devices only`); `.env.example` documents `ALBERT_HTTP_PORT`, `FAIRPLAY_*`, `MITMPROXY_WEB_PASSWORD`, `ALBERT_ACCEPT_RISK`.
- **Validation**: `IMEI`/`UDID`/`Serial` strict regex before `create_activation_record` (`400 validation failed` JSON with `request_id`), `plistlib.loads` with `try/except` → `400 Invalid plist`, `base64 validate False` with padding fix.
- **Hardening**: compose `read_only`, `USER app`, `tini`, `HEALTHCHECK`, `no-new-privileges`, systemd `PrivateTmp NoNewPrivileges`; gunicorn `limit_request_*` + `timeout 30`.
- See `SECURITY.md` for full threat model, TLS posture, key management, incident handling.

## Known Constraints

- IPSW `8.1 GB` external — not in repo; CI must use `*.sha256` manifest (`scripts/sha256_manifest.sh --check`).
- Single host SQLite — not clustered; rate limiter in-memory per worker.
- `mitmproxy` CA must be trusted on device (`http://mitm.it`, profile install, `idevice` trust).
- TSS still Apple-remote — restore SHSH requires Apple `gs.apple.com`.
- Activation bypass may breach Apple ToS / carrier law; legal `NOTICE` + `ALBERT_ACCEPT_RISK` gate.
- iOS 18 TLS pinning `A12+` may require session mode `drmHandshake` or `checkm8 A11-`.
- `.env.example` still `APP_ENV/APP_PORT` legacy placeholder — real `.env` uses `ALBERT_*` names.

## Validation

```bash
pytest && ruff check . && bandit -r .
gunicorn --check-config -c gunicorn_conf.py albert_server:app
curl http://127.0.0.1:18090/health && curl http://127.0.0.1:18090/ready && curl http://127.0.0.1:18090/metrics
curl http://127.0.0.1:18090/dashboard && curl http://127.0.0.1:18090/firmware
curl http://127.0.0.1:18090/api/status | jq .health,.ready,.metrics
curl "http://127.0.0.1:18090/api/firmwares?productType=iPhone11,8" | jq .cached,.stale
docker compose config | grep -E "18090|read_only|cap_drop"
./scripts/sha256_manifest.sh && ./scripts/sha256_manifest.sh --check && git status  # *.ipsw ignored, *.sha256 shown
wc -l docs/architecture.md docs/architecture.md docs/development.md docs/adr/*.md && git diff --stat
```

Record material decisions as ADRs under `docs/adr/` (see `0001-`, `0002-`).
