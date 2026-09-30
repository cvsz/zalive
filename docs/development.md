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
- `make test` → `pytest -q` (118 passed: 12 albert + 14 security gate + 12 activate_device + 5 bootstrap + 5 firmware any-iPhone)
- `make lint` → `ruff check .` (`All checks passed`), `bandit -r . --exclude venv` (`0` with `B303/B324 nosec` for SHA1 ARS)
- `make validate-template` still runs template unittest but project CI uses `ruff+bandit+pytest+docker compose config`.
- Never commit `.env` (`0600`), `certs/fairplay.key` (`0600`), `*.ipsw` (use `*.sha256` manifest via `scripts/sha256_manifest.sh`).

## Reverse engineering tooling (`scripts/`)

Read-only helpers for inspecting Apple firmware and the activation protocol. None of them store
credentials. See `docs/re/` for the findings.

```bash
pip install pyliblzfse capstone          # decompressor + ARM64e disassembler

# Image4 / DER container walk
./venv/bin/python scripts/parse_im4.py <file.im4p>

# LZFSE kernel extraction from a kernelcache
unzip -o iPhone11,8_18.7.10_22H374_Restore.ipsw kernelcache.release.iphone11b -d /tmp/kc
./venv/bin/python scripts/extract_kernel.py /tmp/kc/kernelcache.release.iphone11b -o /tmp/kc/kernel

# Kernel header, PAC census, kext inventory; then a full-segment sweep
./venv/bin/python scripts/analyze_kernel.py /tmp/kc/kernel --disasm 4000000
./venv/bin/python scripts/sweep_kernel.py /tmp/kc/kernel --jobs 3

# Activation protocol — read the live exchange, decode the handshake artifacts
./venv/bin/python scripts/capture_activation_trace.py > trace.json
./venv/bin/python scripts/decode_handshake_artifacts.py
./venv/bin/python scripts/compare_handshake_shapes.py
```

`analyze_kernel.py` and `sweep_kernel.py` need `capstone`; `extract_kernel.py` needs
`pyliblzfse`. Decompressed kernels and sweep output are gitignored (`kernel.decompressed`,
`*.sweep.json`) because they are 54 MiB artifacts.

## Activation helpers (`scripts/`)

```bash
./venv/bin/python scripts/try_activate.py                 # prompts for Apple ID via getpass
./venv/bin/python scripts/diagnose_activation_reject.py   # prints Apple's exact rejection
```

`try_activate.py` reads credentials through `getpass`, never from argv or a file, so they stay
out of shell history and process listings. Both talk to real `albert.apple.com`; that host must
**not** be redirected to `127.0.0.1` in `/etc/hosts`.

## Documentation
Update `docs/architecture.md`, `docs/superpowers/specs/2026-09-28-any-iphone-firmware-design.md`, `SECURITY.md` (0600, 512K, 100/min, redacted UDID) when behavior changes. `docs/re/` holds the reverse-engineering write-ups (`ACTIVATION-PROTOCOL.md`, `IPSW-18.7.10-STRUCTURE.md`, `WORK-REPORT.md`) plus the raw JSON captures.
