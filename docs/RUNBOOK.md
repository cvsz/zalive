# Runbook — Local Albert Production

## Dashboard
- Open `http://192.168.1.123:18090/dashboard` (LAN) or `http://127.0.0.1:18090/dashboard` — 2s poll shows health/ready/fairplay, iPhone identity (redacted), USB, IPSW, recent activations (SQLite), rate, logs tail. APIs: `/api/status`, `/api/activations?limit=5`, `/api/logs?lines=60`, `/` lists endpoints.

## Health
- `curl http://127.0.0.1:18090/health` → 200 liveness
- `curl http://127.0.0.1:18090/ready` → 200 when FairPlay key loaded, 503 otherwise
- `curl http://127.0.0.1:18090/metrics` → prometheus `albert_up`

## Start (host)
```bash
cp .env.example .env  # set MITMPROXY_WEB_PASSWORD, ALBERT_ADMIN_TOKEN, ALBERT_ACCEPT_RISK=1
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

## Restore iPhone (iPhone11,8 through iPhone15,2)
1. Put device in Recovery: `ideviceenterrecovery $UDID` or Home+Power (`idevice_id -l` to discover UDID, e.g. `00008020-AAAAAAAAAAAAAAAA`).
2. Verify: `irecovery -a` or `idevice_id -l` (Recovery) / `lsusb` shows 05ac:12a8.
3. Restore: `idevicerestore -e -y iPhone11,8_18.7.10_22H374_Restore.ipsw` (Erase). Use `-u $UDID` if multiple devices.
   - Run from the **physical host**, not from inside a VM guest with USB passthrough. Passthrough
     re-enumerates the device between Recovery and Restore (`usb 1-1` ⇄ `usb 1-2`) and the handoff
     fails with `Device reconnected in Recovery mode, most likely image personalization failed`.
     `05ac:1280` (Restore Mode) is the mode to watch for; if it never enumerates, suspect transport
     rather than the IPSW. See `docs/re/WORK-REPORT.md` §2.
4. On Hello screen, activation:
   - Against **real Apple** (works when the device's Apple ID is healthy):
     `./venv/bin/python scripts/try_activate.py` — prompts for the Apple ID and password via
     `getpass`, so credentials never reach argv, the process list, or shell history. Requires
     `albert.apple.com` **not** redirected to `127.0.0.1` in `/etc/hosts`.
   - Option A (proxy): Configure device Wi-Fi proxy → `127.0.0.1:28081`, trust CA via `http://mitm.it`.
   - Option B (direct): `python activate_device.py --albert-url http://127.0.0.1:18090 --udid $UDID`

   **The local server cannot activate a device.** The device verifies the FairPlay
   `HandshakeResponseMessage` against Apple's public key; the signing key never appears on the
   wire, so no local response can satisfy the check. The endpoint is kept for protocol research and
   request-handling tests only. See `docs/re/ACTIVATION-PROTOCOL.md`.

## Logs
- `albert.log` (host), `docker compose logs albert-server`, `mitmproxy.log`, `logs/`

## Rotation
```bash
rm certs/fairplay.key certs/fairplay.crt && ./start.sh restart
```
Keys are `0600` persisted; backup `certs/` before rotation.

## Troubleshooting
- `Unable to discover device mode` → USB not passed: VM → Removable Devices → Apple Mobile Device → Connect.
- Port conflict → `ALBERT_HTTP_PORT=18090` already default; check `ss -tln`.
- `413 payload too large` → plist >512KB; device should not send.
- Legal: for owned devices only; `ALBERT_ACCEPT_RISK=1` required to start prod.

## mTLS (proxy → Albert)
- Toggle via `.env` `ALBERT_MTLS_CA=/path/to/ca.pem` (CA bundle that signed `ALBERT_MTLS_CERT`).
- Proxy must present client cert: `ALBERT_MTLS_CERT`/`ALBERT_MTLS_KEY` in `firmware_restore_proxy.py` env.
- HTTP-mode header-only (`X-Client-Cert: present/mtls`) is spoofable; proxy now forwards real PEM or `X-MTLS-Token` (`ALBERT_MTLS_TOKEN`) when set. For production use `LOCAL_ALBERT_SCHEME=https` + gunicorn TLS so `SSL_CLIENT_VERIFY=SUCCESS` (real mTLS). Header fallback is gated by `ALBERT_MTLS_ALLOW_HEADER_FALLBACK` (`1` allows localhost header, `0` rejects spoofable path).
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
- When `ALBERT_REDIS_URL` is set but Redis is unreachable, server logs `WARNING Redis rate limit failed ... falling back to in-memory (request_id=...)` and falls back to per-process in-memory (2 workers → effective `200/min` per IP). Set `ALBERT_REDIS_FAIL_CLOSED=1` to fail closed with `429` instead of degraded fallback.
- Inspect: `curl http://127.0.0.1:18090/api/rate_status` or `GET /api/validate`.

## Logs
- All logs under `logs/` (host: `logs/albert.log`, `logs/mitmproxy.log`, `logs/restore/restore_*.log`, `logs/validate.log`; docker volume `logs:/app/logs`). Old root `*.log` ignored via `.gitignore`.
- `logs/` is gitignored; `logs/.gitkeep` + `logs/restore/README.md` kept. The restore folder is
  re-opened and immediately re-closed (`!logs/restore/` + `logs/restore/*` +
  `!logs/restore/README.md`), so any new file type dropped there stays ignored by default. Restore
  probe logs carry device identifiers (ECID/UDID/serial/IMEI) and must never be committed.
- Retention: SQLite `activations` pruned to `10k` rows + `30d` via `DELETE ... NOT IN (SELECT id ... LIMIT 10000)` in `api_admin/checkpoint` and `albert_server.py` every 100 writes.