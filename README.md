# albert_server — Local Albert Activation Server

Local emulation of Apple's `albert.apple.com` activation endpoints for iOS device activation research and development. Supports iPhone 5 through 15 Pro (A6–A16, 13 curated models).

> **⚠️ Legal Notice**: This tool is for research on **owned devices only**. Activation bypass requires explicit acknowledgement via `ALBERT_ACCEPT_RISK=1`. See [SECURITY.md](SECURITY.md) and [NOTICE](NOTICE).

## Features

- **Activation Endpoints**: `/deviceservices/drmHandshake`, `/deviceservices/deviceActivation`, legacy `/WebObjects/ALUnbrick.woa/wa/deviceActivation`
- **FairPlay Signing**: RSA 2048, SHA1 for ARS (Apple spec), SHA256 for device certs
- **Any-iPhone Support**: Curated devices iPhone 5 → 15 Pro (13 models) with dynamic `ProductType`
- **Firmware Management**: Live `api.ipsw.me` cache (1h TTL) + local `.ipsw` overlay
- **Production Hardening**: 512KB request limit, 100/min IP + 10/min UDID rate limiting, input validation, structured JSON logging
- **mTLS Toggle**: Optional proxy→Albert client certificate verification
- **Observability**: Prometheus metrics (`/metrics`), health/readiness endpoints, AdminLTE 4 dashboard
- **Persistence**: SQLite WAL mode, 10k/30d retention, admin API for checkpoint/prune

## Quick Start

### Prerequisites

- Docker + Docker Compose
- iOS device in DFU/Recovery mode (for activation)
- Apple USB driver (`usbmuxd`, `libimobiledevice`)

### 1. Configure Environment

```bash
cp .env.example .env
# Edit .env: set ALBERT_ADMIN_TOKEN, MITMPROXY_WEB_PASSWORD
# ALBERT_ACCEPT_RISK=1 is required (operator must explicitly opt-in)
```

### 2. Start Services

```bash
docker compose up -d
```

Services:
- **Albert Server**: `http://127.0.0.1:18090` (HTTP) — gunicorn does not terminate TLS; the device-facing TLS is terminated by mitmproxy, and the proxy→Albert hop is plain HTTP gated by `X-MTLS-Token` or a forwarded client cert
- **mitmproxy Web UI**: `http://127.0.0.1:28080` (password from `MITMPROXY_WEB_PASSWORD`)
- **mitmproxy Proxy**: `127.0.0.1:28081`

> **Secure-by-default**: All services bind to `127.0.0.1` on host. For LAN access, set `ALBERT_BIND_ADDRESS=0.0.0.0` in `.env` and configure UFW.

### 3. Install mitmproxy CA on Device

1. Configure device Wi-Fi proxy → `127.0.0.1:28081`
2. Open `http://mitm.it` on device Safari (via proxy)
3. Install "Apple" certificate profile
4. Enable full trust: Settings → General → About → Certificate Trust Settings

### 4. Activate Device

```bash
# Against real Apple — prompts for the Apple ID via getpass (recommended)
./venv/bin/python scripts/try_activate.py

# Print Apple's exact rejection reason
./venv/bin/python scripts/diagnose_activation_reject.py
```

`albert.apple.com` must **not** be redirected to `127.0.0.1` in `/etc/hosts` — the client talks to
Apple directly over USB.

> **A local Albert server cannot activate a real device.** The device verifies the FairPlay
> `HandshakeResponseMessage` against Apple's public key, and the signing key never appears on the
> wire, so no local response satisfies the check. `/deviceservices/*` exists for protocol research
> and request-handling tests. See `docs/re/ACTIVATION-PROTOCOL.md`.
>
> A device with no activation lock simply activates against Apple once it can reach
> `albert.apple.com`. If the account is disabled or iCloud-locked, only the account owner can
> clear it.

## Reverse engineering notes

`docs/re/` holds the write-ups from inspecting a real iPhone11,8 restore:

- `WORK-REPORT.md` — restore, activation and firmware research, including the corrections
- `ACTIVATION-PROTOCOL.md` — the 4 activation hops and the FairPlay trust anchor
- `IPSW-18.7.10-STRUCTURE.md` — 76 components, Image4 DER framing, kernel extraction

## Endpoints

| Endpoint | Description |
|----------|-------------|
| `GET /health` | Liveness probe |
| `GET /ready` | Readiness (FairPlay loaded + cert expiry) |
| `GET /metrics` | Prometheus metrics |
| `GET /dashboard` | Real-time AdminLTE dashboard |
| `GET /firmware` | Firmware browser (13 curated models) |
| `GET /admin` | Admin panel HTML — the page itself is not header-gated; it reads the token from `localStorage` and sends `X-Admin-Token` on its `/api/*` calls, which are the endpoints that enforce auth |
| `POST /deviceservices/drmHandshake` | DRM handshake |
| `POST /deviceservices/deviceActivation` | Device activation |
| `GET /api/status` | JSON status (public: health/ready/version; admin: full) |
| `GET /api/firmwares?productType=X` | Firmware list for device |

## Configuration

All config via environment variables (see `.env.example`):

| Variable | Default | Description |
|----------|---------|-------------|
| `ALBERT_ACCEPT_RISK` | **0** | Legal risk acknowledgement (must set to 1) |
| `ALBERT_BIND_ADDRESS` | `127.0.0.1` | Host publish address (LAN: `0.0.0.0`) |
| `ALBERT_HTTP_PORT` | `18090` | HTTP port |
| `ALBERT_HTTPS_PORT` | `18443` | Published by `docker-compose.yml` but **nothing in the app binds it** — the container is HTTP only. Reserved for an external TLS terminator. |
| `FAIRPLAY_KEY_PATH` | `certs/fairplay.key` | FairPlay private key |
| `ALBERT_ADMIN_TOKEN` | **required** | Admin API token |
| `ALBERT_REDIS_URL` | — | Redis for distributed rate limiting |
| `ALBERT_MTLS_CA` | — | CA bundle for proxy→Albert mTLS |
| `MITMPROXY_WEB_PASSWORD` | **required** | mitmproxy web UI password |

## Development

### Local Run (without Docker)

```bash
pip install -r requirements.txt
export ALBERT_ACCEPT_RISK=1
python3 albert_server.py --host 0.0.0.0 --port 18090
```

### Run Tests

```bash
pytest -q
# or with Docker
docker compose run --rm albert-server pytest -q
```

### Lint & Security

```bash
ruff check .
bandit -r . --exclude ./venv
```

### Rotate FairPlay Keys

```bash
python3 albert_server.py --rotate-fairplay
# Or: rm certs/fairplay.* && docker compose restart albert-server
```

## Architecture

```
iOS Device (HTTPS) → mitmproxy (TLS term, CA) → Albert Server (HTTP)
                                    ↓
                              gs.apple.com (TSS) → Apple (passthrough)
```

- **mitmproxy** intercepts `albert.apple.com` only, rewrites to local Albert
- **TSS** (`gs.apple.com`, `osrecovery.apple.com`) passes through to Apple
- **FairPlay** keys persisted at `certs/` with `0600` perms

## Security

- Request size limit: 512KB (413)
- Input validation: UDID (40 hex / `00008020-*`), IMEI (15 digits), Serial (alphanum) — 400 on fail
- Rate limiting: 100/min/IP + 10/min/UDID (Redis or in-memory)
- Structured JSON logs with `request_id`, UDID redacted
- mTLS proxy→Albert optional (`ALBERT_MTLS_CA`)
- Risk gate: `ALBERT_ACCEPT_RISK=1` required to start

See [SECURITY.md](SECURITY.md) for full policy.

## Troubleshooting

| Issue | Solution |
|-------|----------|
| `ALBERT_ACCEPT_RISK` error | Set `ALBERT_ACCEPT_RISK=1` in `.env` |
| mitmproxy CA not trusted | Reinstall profile, enable full trust in Settings |
| Device not activating | Check USB passthrough, `idevice_id -l`, `lsusb \| grep 05ac` |
| Rate limited (429) | Wait 60s or `POST /api/admin/reset-rate` with admin token |
| FairPlay cert expired | Run `python3 albert_server.py --rotate-fairplay` |

## License

See [LICENSE](LICENSE). Apple trademarks acknowledged in [NOTICE](NOTICE).

## Related

- [docs/DEVICE_GUIDE.md](docs/DEVICE_GUIDE.md) — รุ่นที่รองรับ, ขั้นตอน restore/activate,
  ตัวเลือก CLI, ตัวแปรสภาพแวดล้อม และการแก้ปัญหา
- [docs/RUNBOOK.md](docs/RUNBOOK.md) — ขั้นตอนระดับ production
- [CHANGELOG.md](CHANGELOG.md)
- [CONTRIBUTING.md](CONTRIBUTING.md)
- [docs/startup.md](docs/startup.md) — template bootstrap