# Development — albert_server

## Local setup (Albert)
```bash
git clone https://github.com/cvsz/zalive -b albert-server
cd albert_server
python3 -m venv venv && ./venv/bin/pip install -r requirements.txt
cp .env.example .env  # then ALBERT_HTTP_PORT=18090, ALBERT_ACCEPT_RISK=1, MITMPROXY_WEB_PASSWORD=$(openssl rand -base64 24)
chmod 600 .env
```

## Run (host gunicorn 2×4 on 18090 — prod)
```bash
./start.sh prod        # ALBERT_MODE=prod uses gunicorn -c gunicorn_conf.py
./start.sh status     # checks health/ready/metrics + fairplay.key 0600
./start.sh logs       # albert.log + mitmproxy.log
# or: gunicorn -c gunicorn_conf.py albert_server:app
```

## Run (docker)
```bash
docker compose up -d --build
docker compose logs -f albert-server
curl -s http://127.0.0.1:18090/health|grep ok; curl -s http://127.0.0.1:18090/firmware|head
```

## Quality expectations
- Keep changes small, add tests for `albert_server.py`/`activate_device.py`/`firmware_restore_proxy.py`.
- `make test` → `pytest -q` (18 passed: 12 albert + 6 firmware any-iPhone)
- `make lint` → `ruff check .` (`All checks passed`), `bandit -r . --exclude venv` (`0` with `B303/B324 nosec` for SHA1 ARS)
- `make validate-template` still runs template unittest but project CI uses `ruff+bandit+pytest+docker compose config`.
- Never commit `.env` (`0600`), `certs/fairplay.key` (`0600`), `*.ipsw` (use `*.sha256` manifest via `scripts/sha256_manifest.sh`).

## Documentation
Update `docs/ARCHITECTURE.md`/`architecture.md`, `docs/superpowers/specs/2026-09-28-any-iphone-firmware-design.md`, `SECURITY.md` (0600, 512K, 100/min, redacted UDID) when behavior changes.
