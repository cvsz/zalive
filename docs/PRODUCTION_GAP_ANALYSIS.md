# Production-Grade Gap Analysis — albert_server (iPhone XR Restore)

Date: 2026-09-28  Branch: albert_server  Scope: iPhone11,8_18.7.10 IPSW + Local Albert + mitmproxy activation bypass
Current state: lab-fixed (18090 healthy, IPSW validated 8.1GB, idevicerestore blocked no USB), Flask dev server, ephemeral keys, no tests/CI.

## Summary Score
- Correctness: **needs-change** (functional but brittle)
- Security: **needs-change** (P0 secrets/ephemeral, no auth/TLS)
- Operations: **needs-change** (no readiness/metrics/structured logs)
- Maintainability: **needs-change** (drift reqs, no lint/tests)
- Release: **FAIL** — not production deployable as-is.

## P0 — Must fix before any production exposure

| # | Category | Gap | Evidence | Risk if unaddressed | Fix (smallest) |
|---|----------|-----|----------|---------------------|----------------|
| P0-1 | Security / Crypto | FairPlay private key generated ephemerally on every startup (`rsa.generate_private_key` in `AlbertServer.__init__`), never persisted; `certs/server.crt` is unrelated self-signed `albert.local`. Restart invalidates all previously issued DeviceCertificates → activation records become unverifiable after bounce. | `albert_server.py:36-68` no file load; `certs/` only has nginx-style cert, not FairPlay; `/tmp/albert.log` shows new key each run | Activation flaps, unbrick loop, impossible to rotate safely | Persist FairPlay key+cert to `certs/fairplay.key`/`fairplay.crt` with `0600`, load if exists, add rotation CLI `albert_server.py --rotate-fairplay` |
| P0-2 | Runtime | Flask dev server (`app.run(..., debug=not args.no_debug, use_reloader=False)`) with `debug=True` default. No workers, no graceful shutdown, WARN: “Do not use in production”. Single-threaded → TSS burst DoS. | `albert_server.py:314` + `* Serving Flask app` in `albert.log` | Outage under 2-device concurrent activation, no signal handling | Add `gunicorn` entry: `gunicorn -w 2 -k gthread --threads 4 -b 0.0.0.0:${PORT} albert_server:app --log-level info --timeout 30 --graceful-timeout 10` + `Dockerfile CMD`/`docker-compose command`; keep `__main__` for dev only |
| P0-3 | Interface / Input | No request size/timeout/limit: `MAX_CONTENT_LENGTH` missing, no `plistlib` size guard, `base64.b64decode(validate=False)` accepts huge blobs, no timeout on `sign`/`generate_device_certificate`. Malformed 50 MB plist → memory bomb/DoS. | `albert_server.py` no `app.config[MAX_CONTENT_LENGTH]`; `firmware_restore_proxy.py` no cap | OOM, 1 bad device kills server | Set `MAX_CONTENT_LENGTH=512KB`, `request.get_data(cache=False)` + 10s `Flask` timeout via gunicorn, `plistlib.loads` with 256 KB cap `+ try/except` → 413 |
| P0-4 | TLS | `firmware_restore_proxy` forces `scheme=http` to local Albert even when local is `https:18443`; `start.sh` starts both HTTP+HTTPS on same `certs/server.crt` (CN=albert.local) which is not trusted by iOS; mitmproxy needs its CA installed via `http://mitm.it` undocumented for non-jailbroken | `firmware_restore_proxy.py:39` `scheme=http`, `start.sh:32` dual servers, `certs/server.crt` self-signed 365d | iOS 18 TLS pinning may reject, silent activation fail | Terminate TLS at proxy, use `LOCAL_ALBERT_SCHEME` auto-detect, document CA install + `idevice` trust, or run Albert on plain HTTP behind `mitmproxy` TLS with `insecure` override |
| P0-5 | Secrets | `certs/server.key` `0640` (should be `0600`), `albert_server.py.bak`/`*.bak` left in repo containing old logic (leak surface), `.env.ai`/` .env.provider` at homedir may be swept | `ls -la certs/`: `server.key 1704 0600?` actually `0600` after fix but check → `600` vs `640`; no `.gitignore` | Key exfil, supply-chain | Add `.gitignore` (`*.bak`, `*.log`, `certs/*.key`, `venv/`), `chmod 600 certs/*.key`, never commit IPSW or device identifiers |
| P0-6 | Dependency drift | `requirements.txt` pins `cryptography==42.0.5`/`pyopenssl==24.0.0` but venv has `48.0.1`/`26.2.0` (`pip list`); `requests 2.31.0` warned `urllib3 2.8.0` mismatch; missing `mitmproxy==12.2.3`, `pymobiledevice3==11.19.4` → `pip install` diverges from runtime | `requirements.txt` vs `pip list` above | Non-reproducible builds, supply break on clean clone | Sync pins to actual: `cryptography==48.0.1`, `pyOpenSSL==26.2.0`, `requests==2.31.0`, add `mitmproxy==12.2.3`, `pymobiledevice3==11.19.4`, `gunicorn`, use `pip-tools`/`hash` |

## P1 — Required for reliable operation

| # | Category | Gap | Evidence | Fix |
|---|----------|-----|----------|-----|
| P1-1 | Config | Hardcoded `ALBERT_HTTP_PORT=18090` in `start.sh`/`proxy` but `Dockerfile EXPOSE 8080 8443` and `albert.log` shows `8443` old cert; no `.env.example`, no `12-factor` env (`ALBERT_PORT`, `FAIRPLAY_KEY_PATH`) | `start.sh`, `Dockerfile`, `docker-compose.yml:ports 8080:8080` mismatch | Unify via `env` (`${ALBERT_HTTP_PORT:-18090}`) in all 3, add `.env.example`, document |
| P1-2 | Health | Only `/health` returns `status:ok` without upstream checks; no `/ready` (depends on FairPlay key loaded), no `/live`; `docker-compose healthcheck` still `curl http://localhost:8080/health` (wrong port) | `albert_server.py:/health`, `docker-compose.yml:healthcheck` | Add `/ready` (key+cert exists) and `/live`, fix healthcheck to `$ALBERT_HTTP_PORT`, add `HEALTHCHECK` in Dockerfile |
| P1-3 | Observability | `logging.basicConfig(level=INFO)` plain text, no JSON, no `request_id`/`UDID` redaction, no metrics (`prometheus_client`), `mitmproxy.log` ignored, no alerting | `albert.log`, `mitmproxy.log` plain | Structured JSON logs (`python-json-logger`), `X-Request-ID` middleware, `/metrics`, redacted UDID (`00008020-...2E` → `...2E`) |
| P1-4 | Persistence | `activation_records = {}` in-memory only; no DB, no audit trail; reboot loses history | `albert_server.py:68` | SQLite or file `logs/activations.jsonl` append-only with rotation, plus `GET /admin/activations` auth-gated |
| P1-5 | Error contract | `deviceActivation` now returns 200 even on placeholder cert (good for bypass) but no `X-Apple-Error` semantics; `drmHandshake` returns placeholder sig that real `MobileActivationService` may reject (SHA1 vs SHA256, `ServerSignature` placeholder) | `albert_server.py:201-215` placeholders | Document bypass limitations vs real Apple: sign `ServerSignature` with FairPlay key, or proxy pass-through for real DRM when `ALBERT_PASSTHROUGH=1` |
| P1-6 | Docker | `FROM python:3.11-slim` (should be `3.12`/`3.14` to match `venv 3.14.4`), runs as `root`, no `USER`, no `readOnlyRootFilesystem`, no resource `limits`, `version: '3.8'` deprecated, no `secrets`, binds `0.0.0.0` without need | `Dockerfile`, `docker-compose.yml` | Multi-stage, `RUN useradd app`, `USER app`, `read_only: true`, `tmpfs`, `deploy.resources.limits`, `cap_drop: ALL`, remove `version` |
| P1-7 | Proxy | Single `mitmproxy` instance, `block_global=false` opens proxy to world if exposed; no auth `web_password`, no `mode=upstream` vs `regular` distinction; TSS hosts not handled → restore still needs real Apple `gs.apple.com` (not bypassed) may silently fail | `firmware_restore_proxy.py:ALBERT_HOSTS` fixed but `docker-compose mitmproxy` exposes `8081/8082` to `0.0.0.0` | Bind proxy to `127.0.0.1`, set `web_password` via env, document that TSS must pass through, add `ALBERT_ONLY` toggle |
| P1-8 | Testing | Zero tests; `__pycache__` committed artifact, no `pytest`, no CI, `ls -la .` shows no `Makefile`, `.github/`, `tox.ini` | Repo scan | Add `tests/test_albert.py` (health/drm/activation placeholder+CSR, invalid plist 400, size limit 413), `pytest`, `ruff`, `bandit`, GitHub Actions |
| P1-9 | Recovery | No rollback: `*.bak` files are ad-hoc, no `systemd`/`launchd` graceful stop, `pkill -f albert_server` broad kill may hit unrelated python | `start.sh:stop_services` | Use PID files correctly with `kill -0`, `systemd` unit with `Restart=on-failure`, backup `certs/` before rotate |
| P1-10 | Docs | `README.md:Quick Start` still says `8080` (stale vs `18090` fix), `iproxy 4433 443` wrong for TSS, no `SECURITY.md`, no `RUNBOOK`, no legal disclaimer for activation bypass | `README.md:1-100` | Update ports, add `docs/RUNBOOK.md`, `SECURITY.md`, disclaimer “for testing owned devices only” |

## P2 — Production hardening / polish

- Timeouts/retries: `requests` in `activate_device.py` has fixed `timeout=30` but no retries/backoff for `drmHandshake`; add `tenacity`.
- CORS: no `Access-Control-Allow-Origin` needed (device is not browser) but `OPTIONS` should return 204 not 405 for `/deviceservices/*`.
- Rate limiting: no per-UDID limit → one device brute forces; add `Flask-Limiter` (`100/min` + `10/s` per IP).
- Validation: log current `plurarity` — `plistlib.loads` accepts both XML and binary but activation `AccountToken` fields should be validated (`IMEI` 15 digits, `UDID` 40 hex vs `00008020-...` format).
- Metrics: track `activation_success_total{variant=withCSR|placeholder}` and `drm_handshake_total`.
- Backup: `iPhone11,8_18.7.10_22H374_Restore.ipsw` 8.1 GB should not be in repo (now is) — move to external storage with SHA256 manifest, add `.gitignore *.ipsw`.
- Supply: `libimobiledevice`/`idevicerestore` version pin (`1.0.1` tested) documented in `setup.sh` and `Dockerfile apt-get`.
- Legal: activation bypass may breach Apple ToS / carrier law; add `LICENSE` + `NOTICE` and require `ALBERT_ACCEPT_RISK=1` env to start.

## Minimal production-ready bring-up (next actions, in order)

1. **Persist keys** (`P0-1`): `albert_server.py` load `certs/fairplay.key` if exists else generate+save `0600`; add `openssl x509` SAN.
2. **Gunicorn** (`P0-2`): `requirements.txt` → `gunicorn==21.2.0` + `gunicorn_conf.py`; `Dockerfile CMD ["gunicorn", …]`; `start.sh` `prod` branch.
3. **Limits** (`P0-3`): `app.config['MAX_CONTENT_LENGTH']=512*1024`, `plist` size guard, `gunicorn timeout 30`.
4. **Env parity** (`P1-1`): create `.env.example` (`ALBERT_HTTP_PORT=18090`, `LOCAL_ALBERT_HOST=127.0.0.1`, `FAIRPLAY_KEY_PATH=certs/fairplay.key`), update all 4 files.
5. **Health/readiness** (`P1-2`): `/ready` + fix compose healthcheck.
6. **Tests+CI** (`P1-8`): `tests/test_albert.py` + `pytest` + `ruff` + `bandit` + `.github/workflows/ci.yml`.
7. **Docker hardening** (`P1-6`): non-root, read-only, no `version:`.
8. **Observability** (`P1-3`): JSON logs + `X-Request-ID`.

Validation gates after fixes: `pytest`, `ruff check`, `bandit -r`, `gunicorn --check-config`, `curl /health /ready`, `docker compose config`, `trivy fs` (optional).

