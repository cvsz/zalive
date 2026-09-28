# Startup — albert_server

Generated from `zTemplate` but as existing product (not `Use this template` → `bootstrap.py`). History `5e04f52` GPG `EDDSA` merged `zTemplate` `d9a4e76` via `allow-unrelated-histories`.

## Quick start (Albert)
```bash
git clone https://github.com/cvsz/zalive -b albert-server
cd albert_server
python3 -m venv venv && ./venv/bin/pip install -r requirements.txt
cp .env.example .env  # edit: ALBERT_HTTP_PORT=18090, ALBERT_ACCEPT_RISK=1, MITMPROXY_WEB_PASSWORD=$(openssl rand -base64 24)
chmod 600 .env
./start.sh prod        # or gunicorn -c gunicorn_conf.py albert_server:app
curl -s http://127.0.0.1:18090/health|grep ok; curl -s http://127.0.0.1:18090/firmware|head
```

## Identity
Already applied: `README.md` Local Albert, `ABOUT.md` builder, `CODEOWNERS @cvsz`. `scripts/bootstrap.py` was **not re-run** (would overwrite `README`). Re-running is no-op if same args.

## Manual decisions done
- Language `python:3.14-slim` `3.14.4` venv, `gunicorn 2×4`, `mitmproxy 12.2.3`, port `18090` (was `8080` conflict).
- `LICENSE` MIT retained, add year/holder before public.
- `SECURITY.md` keep `0600`/`429`/`redacted UDID`.

## Next (if re-bootstrapping)
```bash
python3 scripts/bootstrap.py --name albert-server --owner cvsz --codeowner cvsz --description 'Local Albert for iPhone XR restore' --apply
```
Review `git diff` (`README.md`/`ABOUT.md`/`.github/CODEOWNERS` only).
