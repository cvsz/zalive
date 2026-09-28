# Runbook — Local Albert Production

## Dashboard
- Open `http://192.168.1.123:18090/dashboard (LAN via ens33)` (also `http://0.0.0.0:18090/dashboard` in docker) — 2s poll shows health/ready/fairplay, iPhone XR identity (redacted), USB, IPSW, recent activations (SQLite), rate, logs tail. APIs: `/api/status`, `/api/activations?limit=5`, `/api/logs?lines=60`, `/` lists endpoints.

## Health
- `curl http://127.0.0.1:18090/health` → 200 liveness
- `curl http://127.0.0.1:18090/ready` → 200 when FairPlay key loaded, 503 otherwise
- `curl http://127.0.0.1:18090/metrics` → prometheus `albert_up`

## Start (host)
```bash
cp .env.example .env  # set MITMPROXY_WEB_PASSWORD
./start.sh start     # uses gunicorn in prod: ALBERT_HTTP_PORT=18090
./start.sh status
./start.sh logs
```

## Start (docker)
```bash
docker compose up -d --build
docker compose logs -f
curl http://127.0.0.1:18090/health
```

## Restore iPhone XR (iPhone11,8)
1. Put device in Recovery: `ideviceenterrecovery 00008020-001224C81178002E` or Home+Power.
2. Verify: `irecovery -a` or `idevice_id -l` (Recovery) / `lsusb` shows 05ac:12a8.
3. Restore: `idevicerestore -e -y iPhone11,8_18.7.10_22H374_Restore.ipsw` (Erase). Use `-u UDID` if multiple devices.
4. On Hello screen, activation via local Albert:
   - Option A (proxy): `LOCAL_ALBERT_PORT=18090 mitmproxy -s firmware_restore_proxy.py --set block_global=false` then device Wi-Fi proxy → host:18090, trust CA via `http://mitm.it`.
   - Option B (direct): `python activate_device.py --albert-url http://127.0.0.1:18090 --udid 00008020-001224C81178002E`

## Logs
- `albert.log` (host), `docker compose logs albert-server`, `mitmproxy.log`, `logs/`

## Rotation
```bash
rm certs/fairplay.key certs/fairplay.crt && ./start.sh restart
```
Keys are `0600` persisted; backup `certs/` before rotation.

## Troubleshooting
- `Unable to discover device mode` → USB not passed: VM → Removable Devices → Apple Mobile Device → Connect.
- `8080` conflict → `ALBERT_HTTP_PORT=18090` already default; check `ss -tln`.
- `413 payload too large` → plist >512KB; device should not send.
- Legal: for owned devices only; `ALBERT_ACCEPT_RISK=1` required to start prod (future gate).

## mTLS (proxy → Albert)
- Toggle via `.env` `ALBERT_MTLS_CA=/path/to/ca.pem` (CA bundle that signed `ALBERT_MTLS_CERT`).
- Proxy must present client cert: `ALBERT_MTLS_CERT`/`ALBERT_MTLS_KEY` in `firmware_restore_proxy.py` env.
- `gunicorn_conf.py` reads `ALBERT_MTLS_CA` at **import time** (`cert_reqs=2`), not per-request. Changing the var requires full restart:
  ```bash
  sudo systemctl restart albert-server  # systemd
  # or
  ./start.sh restart  # host
  # or
  docker compose restart albert-server  # docker
  ```
- Verify: `curl http://127.0.0.1:18090/health` still 200, but `curl -k https://127.0.0.1:18443/deviceservices/drmHandshake` without cert should 401 when mTLS on.

## Rate limiting
- Defaults `100/min per IP` + `10/min per UDID` (env `ALBERT_REDIS_URL` → Redis `INCR+EXPIRE` distributed, else in-memory per-worker).
- When `ALBERT_REDIS_URL` is set but Redis is unreachable, server logs `WARNING Redis rate limit degraded to in-memory...` and falls back to per-process in-memory (2 workers → effective `200/min` per IP). To fail closed set `ALBERT_REDIS_REQUIRED=1` (future).
- Inspect: `curl http://127.0.0.1:18090/api/rate_status` or `GET /api/validate`.

## Logs
- All logs under `logs/` (host: `logs/albert.log`, `logs/mitmproxy.log`, `logs/restore/restore_*.log`, `logs/validate.log`; docker volume `logs:/app/logs`). Old root `*.log` ignored via `.gitignore`.
- `logs/` is gitignored; `logs/.gitkeep` + `logs/restore/README.md` kept.
- Retention: SQLite `activations` pruned to `10k` rows + `30d` via `DELETE ... NOT IN (SELECT id ... LIMIT 10000)` in `api_admin/checkpoint` and `albert_server.py` every 100 writes.

