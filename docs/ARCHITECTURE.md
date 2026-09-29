# Architecture — albert_server (Local Albert for iPhone 5→15 Pro)

## Overview
Local emulator of `albert.apple.com` for iOS restore/activation testing (iPhone11,8 through iPhone15,2, 13 curated models).
All activation is **local**; TSS (`gs.apple.com`) passes through to Apple unless a local TSS is explicitly enabled.
Production entry is `gunicorn` (`gunicorn_conf.py`); dev fallback is `python albert_server.py`.

## Diagram (ports: 18090 Albert, 28080/28081 mitmproxy)

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
 │   │ build: . (3.13-slim)│──▶│ image: 12.2.3        │                     │
 │   │ USER app, readOnly  │   │ 127.0.0.1:28080/28081│                     │
 │   │ ports 18090,18443   │   │ web_password=$MITMP..│                     │
 │   │ healthcheck /health │   │ depends_on healthy   │                     │
 │   └─────────────────────┘   └─────────────────────┘                     │
 │   network: albert-network (bridge)   volumes: certs:ro, logs           │
 └─────────────────────────────────────────────────────────────────────────┘
```

IPSW: `iPhone11,8_18.7.10_22H374_Restore.ipsw` (8.1 GB) — NOT in repo, stored externally; `scripts/sha256_manifest.sh` produces `*.ipsw.sha256` + `ipsw.sha256`. `.gitignore` ensures `*.ipsw` ignored but `*.sha256` kept (`!*.sha256`).

## Components

| Component | File | Role | Port / bind |
|-----------|------|------|-------------|
| Albert server | `albert_server.py` | Flask app: `/deviceservices/drmHandshake`, `/deviceActivation`, `/WebObjects/ALUnbrick…`, `/health`, `/ready`, `/metrics`, `/certifyMe`, `/activity`, `/phoneHome` | Container: `0.0.0.0:18090`; Host publish: `ALBERT_BIND_ADDRESS:18090` (default `127.0.0.1`) |
| Gunicorn | `gunicorn_conf.py` | Prod WSGI: `gthread`, `workers=2 threads=4`, `timeout 30`, `graceful 10`, `limit_request_*`, JSON access log with `X-Request-ID` | `bind = $ALBERT_HOST:$ALBERT_HTTP_PORT` (container `0.0.0.0:18090`) |
| Proxy | `firmware_restore_proxy.py` | mitmproxy addon: only `albert.apple.com` → local; `gs.apple.com` pass-through; adds `X-Forwarded-*` | `LOCAL_ALBERT_HOST:LOCAL_ALBERT_PORT` → `albert-server:18090` |
| Activation client | `activate_device.py` | Direct `POST` to Albert without proxy (alternative to Wi-Fi proxy) | `--albert-url http://127.0.0.1:18090` |
| Compose | `docker-compose.yml` | Two-service stack, `read_only`, `cap_drop ALL`, `no-new-priv`, `healthcheck /health` | Albert: `18090`/`18443`; mitmproxy: `28080`/`28081` (host `127.0.0.1`) |
| Dockerfile | `Dockerfile` | `python:3.13-slim`, `tini`, `useradd app`, `USER app`, `HEALTHCHECK`, `--require-hashes` | `EXPOSE 18090 18443` |

## Request Flow

1. **drmHandshake** (session): Device sends `HandshakeRequestMessage` (+ optional CSR) → Albert returns `ServerCertificate` (FairPlay chain), `ServerRandom`, `SessionID`, `ServerSignature` (placeholder). No Apple contact.
2. **deviceActivation**: Device sends `activation-info` (base64 plist, form `activation-info`, or `application/x-apple-plist`). Albert validates `IMEI`/`UDID`/`Serial`, generates or reuses `DeviceCertificate` from CSR, signs `AccountToken` with FairPlay `SHA1` (Apple-spec `ARS` header), returns `activation-record` plist with `AccountToken`, `DeviceCertificate`, `FairPlayKeyData`, `WildcardTicket`. Persisted to `logs/activations.db` + in-memory.
3. **TSS** (`gs.apple.com/TSS/controller?action=2`): Not intercepted; allowed to reach Apple for SHSH. Proxy logs keyword `tss` but does not redirect (see `TSS_HOSTS` empty).
4. **Health**: `GET /health` always `200` (liveness). `GET /ready` is `200` iff `FAIRPLAY_CERT_CHAIN` loaded, else `503`. `GET /metrics` emits `albert_up`, `albert_activation_total`.

## Data and Persistence

- **Keys**: `certs/fairplay.key`/`fairplay.crt` (`0600`, PEM, RSA 2048, CA `Apple iPhone Device CA`, 5 y, `SHA256`). Generated once; `chmod 600` enforced. `certs/server.crt/key` for dev HTTPS only (`CN=albert.local`, `365 d`).
- **Activations**: SQLite `logs/activations.db` (`WAL`, table `activations(id, udid, serial, created_at, record, producttype)` with `UNIQUE(udid) ON CONFLICT REPLACE`), host volume `logs:/app/logs` in compose. `logs/` is `.gitignore`'d; DB is `0600` via umask.
- **Logs**: `python-json-logger` JSON (`timestamp`, `level`, `name`, `message`, `request_id`, `remote_addr`) or plain fallback; `X-Request-ID` middleware (`uuid4`); `UDID` suffix-only (`…2E`); `albert.log`, `mitmproxy.log`, `logs/` all gitignored.
- **IPSW**: `iPhone11,8_18.7.10_22H374_Restore.ipsw` (8.1 GB) external; `scripts/sha256_manifest.sh` emits `*.ipsw.sha256` + `ipsw.sha256` (tracked), `*.ipsw` ignored.

## Security Integration

See `SECURITY.md` for threat model, TLS posture (`mitmproxy` CA via `http://mitm.it`, `LOCAL_ALBERT_SCHEME=http` behind TLS), key `0600`, and `ALBERT_ACCEPT_RISK=1` gate. `NOTICE` carries Apple ToS disclaimer. `.env.example` provides `ALBERT_BIND_ADDRESS=127.0.0.1`, `ALBERT_HTTP_PORT=18090`, `FAIRPLAY_*`, `MITMPROXY_WEB_PASSWORD`, `ALBERT_ACCEPT_RISK=0`. `.gitignore` keeps `*.ipsw` out and `*.sha256` in.

## Production vs Dev

| Mode | Command | Server | TLS | Risk gate |
|------|---------|--------|-----|-----------|
| prod (default) | `docker compose up -d` | `gunicorn -c gunicorn_conf.py albert_server:app` | `mitmproxy` terminates TLS; Albert `http` | `ALBERT_ACCEPT_RISK=1` required |
| dev | `python albert_server.py --host 0.0.0.0 --port 18090` | Flask dev server | Optional `certs/server.crt/key` on `18443` | Same gate |
| docker | `docker compose up -d --build` | `gunicorn` in container | Same as prod | Env `ALBERT_ACCEPT_RISK=1` |

## Failure Modes

- `18090` busy → `start.sh` reports `ss -tln` hint; already defaulted from `8080` (occupied by host nginx/fastapi) to `18090`.
- `ALBERT_ACCEPT_RISK != 1` → `start.sh`/`gunicorn` abort with message (see `SECURITY.md`).
- `413` → plist >512 KB (device bug).
- `503 /ready` → FairPlay key missing/corrupt; check `ls -l certs/` and `albert.log`.
- `block_global=true` (not set) would expose proxy globally — fixed to `false` with `127.0.0.1` host bind.

## Validation

```bash
pytest && ruff check . && bandit -r .
gunicorn --check-config -c gunicorn_conf.py albert_server:app
curl http://127.0.0.1:18090/health && curl http://127.0.0.1:18090/ready
docker compose config
./scripts/sha256_manifest.sh && git status  # *.ipsw ignored, *.sha256 shown
```