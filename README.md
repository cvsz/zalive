# Local Albert Activation Server for iOS Firmware Restore

A complete solution for activating iOS devices after firmware restore using a local Albert activation server with proxy interception.

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        iOS Device                               │
│  (in Recovery/DFU mode or normal boot)                         │
└──────────────────────┬──────────────────────────────────────────┘
                       │ USB / Network
                       ▼
┌─────────────────────────────────────────────────────────────────┐
│                     Host Computer                               │
│  ┌─────────────────┐    ┌─────────────────────────────────┐    │
│  │  mitmproxy      │───▶│  Local Albert Server (Flask)    │    │
│  │  (Interceptor)  │    │  Port 18090 (gunicorn prod)     │    │
│  └─────────────────┘    └─────────────────────────────────┘    │
│         │                                                │       │
│         │ HTTPS (443)                                    │       │
│         ▼                                                ▼       │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │  Apple Servers (albert.apple.com, gs.apple.com, etc.)   │   │
│  │  [BLOCKED/REDIRECTED: albert only; TSS pass-through]    │   │
│  └─────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
```

See `docs/ARCHITECTURE.md` for the full fixed-port (18090) diagram with gunicorn, TLS termination, SQLite, and `mitmproxy` layout.

## Components

1. **`albert_server.py`** - Flask-based local Albert activation server (gunicorn in prod)
2. **`firmware_restore_proxy.py`** - mitmproxy script to intercept and redirect traffic
3. **`activate_device.py`** - Python client for device activation
4. **`setup.sh`** - Automated setup script
5. **`gunicorn_conf.py`** - Production WSGI config (`18090`, `gthread`, `workers=2`)
6. **`docker-compose.yml`** - Prod stack (albert-server + mitmproxy, `read_only`, `127.0.0.1` binds)

## Prerequisites

### System Requirements
- Linux (Ubuntu 20.04+/Debian 11+) or macOS
- Python 3.14 (matches `Dockerfile python:3.14-slim`; `3.9+` minimum)
- USB access for iOS device connection

### Required Tools
```bash
# Ubuntu/Debian
sudo apt update && sudo apt install -y \
    python3 python3-pip python3-venv \
    libimobiledevice-utils usbmuxd \
    mitmproxy \
    libssl-dev libusb-1.0-0-dev libplist-dev \
    libimobiledevice-dev libideviceactivation-dev

# macOS (via Homebrew)
brew install python3 libimobiledevice usbmuxd mitmproxy
```

### Python Dependencies
```bash
cd albert_server
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt  # flask 3.0.0, cryptography 48.0.1, pyOpenSSL 26.2.0, gunicorn 21.2.0, mitmproxy 12.2.3, pymobiledevice3 11.19.4
```

## Quick Start

### 1. Setup Everything
```bash
chmod +x setup.sh
./setup.sh
```

### 2. Start the Local Albert Server
```bash
source venv/bin/activate
python albert_server.py --host 0.0.0.0 --port 18090
```

### 3. Start the Proxy (in another terminal)
```bash
source venv/bin/activate
mitmproxy -s firmware_restore_proxy.py --set block_global=false
```

### 4. Configure iOS Device to Use Proxy

#### Option A: WiFi Proxy (for normal boot)
1. On iOS device: Settings → WiFi → (i) → Configure Proxy → Manual
2. Server: `<host-computer-ip>`
3. Port: `18090`
4. Install mitmproxy CA certificate: http://mitm.it

#### Option B: USB with iproxy (for recovery/DFU mode)
```bash
# Forward device proxy to host 18090
iproxy 18090 18090

# For TSS (gs.apple.com) on port 443 — pass-through to Apple, not local
iproxy 4433 443
```

### 5. Activate Device
```bash
# Check device connection
idevice_id -l

# Activate (default port 18090)
python activate_device.py --udid <DEVICE_UDID> --albert-url http://127.0.0.1:18090
```

## Production Quick Start (gunicorn + docker)

Host port `8080` is occupied on this machine (nginx/fastapi); production uses **`18090`** everywhere (`ALBERT_HTTP_PORT=18090` in `.env.example`, `start.sh`, `gunicorn_conf.py`, `docker-compose.yml`, `firmware_restore_proxy.py`, `docs/ARCHITECTURE.md`).

### Host (gunicorn)
```bash
cp .env.example .env
# Edit .env: set MITMPROXY_WEB_PASSWORD and ALBERT_ACCEPT_RISK=1 (required, see SECURITY.md)
chmod 600 certs/*.key 2>/dev/null || true
./start.sh prod
# or: ALBERT_MODE=prod ./start.sh start
curl http://127.0.0.1:18090/health   # 200 liveness
curl http://127.0.0.1:18090/ready    # 200 when FairPlay key loaded, 503 otherwise
curl http://127.0.0.1:18090/metrics  # prometheus albert_up
./start.sh status
./start.sh logs
```

Direct gunicorn (without start.sh):
```bash
export ALBERT_ACCEPT_RISK=1
export ALBERT_HTTP_PORT=18090
gunicorn -c gunicorn_conf.py albert_server:app --access-logfile - --error-logfile -
# gunicorn binds $ALBERT_HOST:$ALBERT_HTTP_PORT (gunicorn_conf.py: ALBERT_HOST/ALBERT_HTTP_PORT)
```

### Docker
```bash
cp .env.example .env
# set MITMPROXY_WEB_PASSWORD and ALBERT_ACCEPT_RISK=1 in .env
docker compose up -d --build
docker compose logs -f
curl http://127.0.0.1:18090/health
curl http://127.0.0.1:18090/ready
docker compose down
```

### Verify Production Stack
```bash
# health/readiness
curl -s http://127.0.0.1:18090/health | grep -q '"status":"ok"' && echo "health ok"
# config (no version: key, read_only, cap_drop, USER app)
docker compose config | grep -E "18090|read_only|cap_drop|user:"
# IPSW not committed, manifest kept
./scripts/sha256_manifest.sh        # generates *.ipsw.sha256 + ipsw.sha256 without committing *.ipsw
git status                         # *.ipsw ignored, *.sha256 tracked
./scripts/sha256_manifest.sh --check  # verify
# TLS (mitmproxy CA)
# Device Wi-Fi proxy → host:18090, then http://mitm.it to install CA
```

## Detailed Usage

### Firmware Restore Flow

1. **Put device in Recovery Mode**
   ```bash
   ideviceenterrecovery <UDID>
   ```

2. **Restore with idevicerestore (using proxy)**
   ```bash
   # Set proxy environment variables (prod port 18090)
   export HTTPS_PROXY=http://127.0.0.1:18090
   export HTTP_PROXY=http://127.0.0.1:18090
   
   # Restore with idevicerestore (from libimobiledevice)
   idevicerestore -e latest.ipsw
   ```

3. **After restore, device will attempt activation**
   - Traffic goes through mitmproxy
   - Only `albert.apple.com` redirected to local Albert (`18090`); `gs.apple.com` (TSS) passes through to Apple
   - Local server returns valid activation record
   - Device activates without Apple albert servers

### Manual Activation (Post-Restore)

If device boots to Hello screen but won't activate:

```bash
# Pair device first
idevicepair pair

# Check activation state
ideviceactivation state

# Activate via local server (port 18090)
python activate_device.py --udid <UDID> --albert-url http://127.0.0.1:18090
```

### Using with pymobiledevice3 (Alternative)

```bash
pip install pymobiledevice3

# Activate directly
pymobiledevice3 mobileactivation activate --skip-apple-id-query
```

## Configuration

### Albert Server Options
```bash
python albert_server.py --help

# Options:
#   --host HOST          Host to bind (default: 0.0.0.0)
#   --port PORT          Port to bind (default: 18090)
#   --ssl-cert FILE      SSL certificate for HTTPS
#   --ssl-key FILE       SSL private key for HTTPS
# Env (12-factor, .env.example):
#   ALBERT_HTTP_PORT=18090  ALBERT_HTTPS_PORT=18443  ALBERT_HOST=127.0.0.1
#   FAIRPLAY_KEY_PATH=certs/fairplay.key  FAIRPLAY_CERT_PATH=certs/fairplay.crt
#   LOCAL_ALBERT_HOST/PORT/SCHEME, MITMPROXY_WEB_PASSWORD, ALBERT_ACCEPT_RISK=1
```

### Generate SSL Certificates (for HTTPS dev)
```bash
openssl req -x509 -newkey rsa:2048 -nodes -keyout server.key -out server.crt \
    -days 365 -subj "/CN=albert.local"
chmod 600 server.key

# Run with SSL (dev, 18443)
python albert_server.py --ssl-cert server.crt --ssl-key server.key --port 18443
# Prod uses gunicorn on 18090 behind mitmproxy TLS (see SECURITY.md TLS)
```

### Proxy Configuration
Edit `firmware_restore_proxy.py` to customize:
- `LOCAL_ALBERT_HOST` - Local server IP (env `LOCAL_ALBERT_HOST`, default `127.0.0.1`, `albert-server` in docker)
- `LOCAL_ALBERT_PORT` - Local server port (env `LOCAL_ALBERT_PORT`, default `18090`)
- `LOCAL_ALBERT_SCHEME` - `http` (default, behind mitmproxy TLS) or `https`
- `ALBERT_HOSTS` - Hosts to intercept (`albert.apple.com` only; `gs.apple.com` pass-through)

## Troubleshooting

### Device Not Detected
```bash
# Check USB connection
lsusb | grep -i apple

# Restart usbmuxd
sudo systemctl restart usbmuxd

# Re-pair
idevicepair unpair && idevicepair pair
```

### Proxy Not Intercepting
```bash
# Check mitmproxy logs
mitmproxy -s firmware_restore_proxy.py --set block_global=false -v

# Verify proxy is running (prod port 18090)
curl -x http://127.0.0.1:18090 http://httpbin.org/ip
# Albert direct
curl http://127.0.0.1:18090/health
curl http://127.0.0.1:18090/ready
```

### Activation Fails
1. Check Albert server logs for errors (`albert.log` or `docker compose logs albert-server`)
2. Verify device UDID matches activation record
3. Check if device is iCloud locked (requires Apple ID)
4. Ensure correct IMEI/MEID for cellular devices
5. Check `ALBERT_ACCEPT_RISK=1` is set (see `SECURITY.md` risk gate; prod refuses without it)
6. For TLS pinning on A12+/iOS 18, use session mode (`drmHandshake`) or checkm8 `A11-`

### Certificate Pinning Issues
Modern iOS versions pin Apple certificates. Solutions:
1. **Use checkm8 devices (A5-A11)**: No certificate pinning in DFU
2. **Patch mobileactivationd**: Requires jailbreak
3. **Use session-based activation**: A12+ devices with valid DRM handshake (`/deviceservices/drmHandshake`)

## Supported Devices & iOS Versions

| Device Range | Chip | iOS Version | Method |
|--------------|------|-------------|--------|
| iPhone 5s - X | A7-A11 | 12-16.x | checkm8 + local Albert |
| iPhone XS - 14 | A12-A16 | 15-17.x | Session activation* |
| iPhone 15+ | A17+ | 17+ | Session activation* |

*Session activation requires valid DRM handshake with FairPlay keys (`certs/fairplay.key` `0600` persisted, see `SECURITY.md`).

## Security Notes

⚠️ **IMPORTANT LEGAL NOTICE**
- This tool is for **educational and research purposes only**
- Only use on devices you own or have explicit permission to test
- Bypassing activation lock on stolen/lost devices is illegal
- Respect Apple's Terms of Service and applicable laws — see `NOTICE` (Apple ToS disclaimer)
- Production requires `ALBERT_ACCEPT_RISK=1` — no bypass without it (see `SECURITY.md` Risk Gate, Threat Model, TLS, Key Management `0600`)
- Keys are `0600`: `certs/fairplay.key`, `certs/server.key` (see `SECURITY.md`)
- IPSW (`*.ipsw` 8.1 GB) is not committed; `scripts/sha256_manifest.sh` tracks `*.sha256` only (`.gitignore` keeps manifest)

## How It Works

### Activation Protocol Flow

1. **Device → Albert**: `drmHandshake` (session mode) or direct `deviceActivation`
2. **Albert → Device**: Returns signed activation record with:
   - `AccountToken` (device identity + certificates)
   - `DeviceCertificate` (signed by Apple iPhone Device CA, via FairPlay `0600` key)
   - `FairPlayKeyData` (DRM keys)
   - `WildcardTicket` (cellular activation)
3. **Device**: Validates signatures, stores record, activates

### Local Server Implementation

The local Albert server:
- Generates RSA keys for FairPlay signing (`certs/fairplay.key` persisted `0600`, `gunicorn` prod, not Flask dev)
- Creates valid X.509 device certificates from CSR
- Signs activation records with FairPlay private key
- Returns properly formatted plist responses with `MAX_CONTENT_LENGTH=512KB`, `X-Request-ID`, rate limit `100/min`
- Includes ARS (Apple Response Signature) header (`SHA1` Apple-spec)
- Persists to SQLite `logs/activations.db` (WAL), exposes `/health`, `/ready`, `/metrics`

## Files Structure

```
albert_server/
├── albert_server.py              # Flask server (prod: gunicorn, dev: python)
├── gunicorn_conf.py              # Gunicorn prod config (18090, gthread, 2×4)
├── firmware_restore_proxy.py     # mitmproxy interceptor (only albert.apple.com)
├── activate_device.py            # Activation client
├── setup.sh / start.sh           # Setup and prod/dev start (ALBERT_MODE, 18090)
├── docker-compose.yml / Dockerfile  # Prod stack (python:3.14-slim, USER app, readOnly)
├── certs/                        # fairplay.key (0600) / fairplay.crt (0600) / server.crt/key
├── logs/                         # activations.db (WAL) + albert.log (gitignored)
├── docs/
│   ├── PRODUCTION_GAP_ANALYSIS.md
│   ├── RUNBOOK.md                # health/ready, start host/docker, restore XR, rotation
│   └── ARCHITECTURE.md           # fixed 18090 diagram
├── scripts/sha256_manifest.sh    # SHA256 manifest for IPSW without committing IPSW
├── SECURITY.md                   # threat model, TLS, key 0600, ALBERT_ACCEPT_RISK=1 gate
├── LICENSE                       # MIT
├── NOTICE                        # Apple ToS disclaimer
├── .env.example                  # 12-factor env (ALBERT_HTTP_PORT=18090, ALBERT_ACCEPT_RISK)
├── .gitignore                    # *.ipsw ignored, *.sha256 kept
├── requirements.txt
└── README.md                     # this file
```

## Compliance

- **SECURITY.md** — full threat model, TLS (mitmproxy CA via `http://mitm.it`, `LOCAL_ALBERT_SCHEME`), key management `0600`, `ALBERT_ACCEPT_RISK=1` gate (no bypass without it)
- **NOTICE** + **LICENSE** — Apple ToS disclaimer (owned devices only) + MIT
- **docs/RUNBOOK.md** — health/ready, host vs docker start, iPhone XR restore, rotation (`rm certs/fairplay.* && ./start.sh restart`, `0600`), troubleshooting
- **docs/ARCHITECTURE.md** — fixed `18090` diagram, component table, request flow, persistence
- **scripts/sha256_manifest.sh** — `sha256sum` manifest for `*.ipsw` without committing the 8.1 GB file

## License

MIT License — see `LICENSE`. For educational and research purposes only. Apple ToS disclaimer in `NOTICE`.

## What we can do now (after prod hardening)

**Live stack (verified `18090`):**
- `GET /health` → `ok` (liveness), `GET /ready` → `fairplay_loaded:true` (readiness, `503` if key missing), `GET /metrics` → `prometheus_client` (`albert_up`, `activations`)
- `POST /deviceservices/drmHandshake` (session mode) + `POST /deviceservices/deviceActivation` (form `activation-info` base64 or raw plist) → signed `iphone-activation.activation-record` + `ARS` header; no `b""` crashes (fallback placeholder cert if CSR missing)
- Proxy: `firmware_restore_proxy.py` intercepts only `albert.apple.com` (TSS `gs.apple.com` passes through to Apple), env-driven `LOCAL_ALBERT_HOST/PORT/SCHEME`
- Persistence: FairPlay key `certs/fairplay.key` `0600` persisted across restarts (was ephemeral), SQLite `logs/activations.db` WAL (audit trail), IPSW `8.1 GB` `b30474b...` manifest `*.sha256` not committed
- Runtime: `gunicorn -c gunicorn_conf.py` `gthread 2×4 timeout 30` (dev `python albert_server.py` still works), `Dockerfile python:3.14-slim tini USER app read_only:true cap_drop:ALL 0600`, `docker-compose.yml` `127.0.0.1` binds + `healthcheck`
- Security: `MAX_CONTENT_LENGTH=512KB` → `413 json`, per-IP rate limit `100/min` → `429`, UDID/IMEI validation → `400`, `X-Request-ID` UUID echo + JSON logs, `SECURITY.md` risk gate `ALBERT_ACCEPT_RISK=1`, `Bandit` clean (`nosec B303/B324` Apple SHA1 spec), `0600` keys
- Client: `activate_device.py` base64 fix + retries `3` exponential `1s/2s/4s` for `413/429/5xx/timeout`, `X-Request-ID`, `UDID/IMEI` validation, `--json`/`--timeout`/`--retries` flags, structured logs
- Tests/CI: `tests/test_albert.py` `12 passed` (`health/ready/metrics/drm/with/without CSR/invalid/size/options/rate-limit/invalid-imei/persistence`), `ruff All checks passed`, `bandit 0`, `docker compose config ok`, `venv py_compile OK`, `make test`

**Dashboard realtime (new):** `http://127.0.0.1:18090/dashboard` — dark UI, 2s poll `/api/status` (health/ready/fairplay 0600, metrics `activations/wal`, iPhone XR `MT1A2TH/A` redacted `0000...002E`, USB `05ac`, IPSW `b304...`) + `/api/activations` (SQLite WAL 5 recent) + `/api/logs?lines=60` tail, auto-refresh. `GET /` now lists `["/dashboard","/api/status","/health",...]`.

**Try now:**
```bash
cp .env.example .env  # then ALBERT_ACCEPT_RISK=1 + MITMPROXY_WEB_PASSWORD=$(openssl rand -base64 24)
chmod 600 .env
./start.sh prod  # or: docker compose up -d --build
curl -s http://127.0.0.1:18090/health | grep ok
curl -s http://127.0.0.1:18090/ready
curl -s http://127.0.0.1:18090/metrics | head
pytest -q  # 12 passed
./scripts/sha256_manifest.sh --check
# Restore (needs USB passthrough, otherwise "Unable to discover device mode"):
idevice_id -l  # or irecovery -a / lsusb 05ac
idevicerestore -e -y iPhone11,8_18.7.10_22H374_Restore.ipsw
python activate_device.py --albert-url http://127.0.0.1:18090 --udid 00008020-001224C81178002E --json
```

## What next (roadmap, P2 polish)

**Reliability:**
- Distributed rate limit (Redis) + per-UDID limit (currently per-IP in-memory, per-worker isolated)
- SQLite → Postgres for multi-host, plus `GET /admin/activations` (auth) + retention rotation
- `ALBERT_PASSTHROUGH=1` for real DRM when FairPlay placeholder insufficient on A12+ iOS 18 `mobileactivationd`

**Observability:**
- `prometheus_client` counters already wired → add Grafana dashboard + alert `albert_up==0` / `rate(albert_activation_failures_total[5m])>0.05`
- OpenTelemetry traces for `drmHandshake→deviceActivation` correlation by `X-Request-ID`

**Security:**
- Replace SHA1 ARS with stronger + `nosec` doc, add mTLS for proxy→Albert, rotate FairPlay via `albert_server.py --rotate-fairplay`
- Wire `tenacity` (dead import removed) or keep manual loop + add circuit breaker

**Ops:**
- `systemd/albert-server.service` already exists → `systemctl enable --now`; add `launchd` for macOS
- Supply pin with hashes (`pip-tools`), `trivy fs` scan in CI

**Compliance:** keep `NOTICE` Apple ToS / owned-devices-only; `ALBERT_ACCEPT_RISK=1` gate already enforced



## Firmware Pages (any iPhone)

Live catalog from `https://api.ipsw.me/v4/device/{ProductType}` cached `1h` in `logs/firmware_cache.json` (`0600`) + local scan `*.ipsw` overlay.

- `GET /firmware` — dark table: Version | Build | Released | Size | Signed `✓`/`✗` | Local `✅` | Download `⬇` (Apple `url`). Dropdown curated `iPhone11,8` XR · `iPhone12,1` 11 · `iPhone13,2` 12 · `iPhone14,5` 13 · `iPhone15,2` 14 Pro + search filter, `cached`/`stale` banner.
- `GET /api/devices` → `{"devices": [5]}` (curated `identifier/name/chip/internal`).
- `GET /api/firmwares?productType=iPhone13,2` → `{"firmwares": [...], "local": [...], "cached": bool, "fetchedAt": iso, "stale": bool}` — `400` if `^iPhone\d+,\d+$` fails, `502` if upstream down and no cache, `8s` timeout.

Any-iPhone: `GET /api/status` `device` now reads last `activations` row’s `producttype` (fallback XR `MT1A2TH/A 00008020-001224C81178002E`); dashboard header `Albert — Any iPhone`.

Try:
```bash
curl -s http://127.0.0.1:18090/api/devices | python3 -m json.tool
curl -s "http://127.0.0.1:18090/api/firmwares?productType=iPhone11,8" | python3 -c "import json,sys; d=json.load(sys.stdin); print(len(d['firmwares']), d['firmwares'][0]['version'])"
# open http://127.0.0.1:18090/firmware (also http://0.0.0.0:18090/firmware)
```

## References

- [libimobiledevice](https://libimobiledevice.org/)
- [libideviceactivation](https://github.com/libimobiledevice/libideviceactivation)
- [pymobiledevice3](https://github.com/doronz88/pymobiledevice3)
- [The iPhone Wiki - Albert](https://theapplewiki.com/wiki/Albert)
- [Hana's Blog - Activation Research](https://hanakim3945.github.io/)
