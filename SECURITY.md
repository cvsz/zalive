# Security Policy — albert_server

## Overview
`albert_server` is a **local** Apple Albert activation emulator for iPhone restore
testing on devices you own. It bypasses Apple activation, which may violate
Apple Terms of Service and carrier/circumvention laws — see `NOTICE`.
Do not expose this server to the Internet. Bind to `127.0.0.1` by default and
require explicit risk acceptance to start.

## Risk Gate
**No bypass without `ALBERT_ACCEPT_RISK=1`.**

- Production (`ALBERT_MODE=prod`, `gunicorn`, `docker compose`) refuses to start
  unless the environment contains `ALBERT_ACCEPT_RISK=1`.
- Host dev (`ALBERT_MODE=dev`) also checks the variable and exits with a
  clear error if it is not `1`, unless `--allow-no-risk` is passed explicitly
  for local lab use (the bypass is then still logged as un-acknowledged).
- `start.sh` aborts before launching `gunicorn`/`mitmproxy` if the gate fails.
- CI (`tests/test_albert.py`) verifies the gate.

Set it per-run or in `.env`:

```bash
export ALBERT_ACCEPT_RISK=1
# or
echo ALBERT_ACCEPT_RISK=1 >> .env
./start.sh prod
# docker
ALBERT_ACCEPT_RISK=1 docker compose up -d --build
```

If you need to evaluate without accepting the legal risk, do not run the
activation endpoints — use `curl /health` in a sandbox with TSS/activation
intercept disabled.

## Threat Model

| Threat | Asset | Attack vector | Impact | Mitigation implemented |
|--------|-------|---------------|--------|------------------------|
| Key exfiltration | `certs/fairplay.key`, `certs/server.key` | Repo commit, world-readable file, log leak, backup scrape | Forged activation records, impersonation | `0600` on `*.key`/`fairplay.crt`, `.gitignore` `certs/*.key`, `certs/*.crt`, `*.pem`, ephemeral keys not reused, `chmod 0600` on persist, no key material in logs, `bandit`/`ruff` in CI |
| Activation bypass misuse | Owned vs stolen device | Stolen device activated, iCloud lock bypass | Legal liability (carrier/anti-circumvention) | `ALBERT_ACCEPT_RISK=1` gate, `NOTICE`/`LICENSE` disclaimer, `UDID` redacted in logs (`…2E`), audit log `logs/activations.db` (SQLite WAL) with `0600` |
| DoS (memory/CPU) | Flask/put parsing | 50 MB `plist`/`base64` blob, no timeout | OOM, worker starvation | `MAX_CONTENT_LENGTH=512KB` (`413`), `plistlib` 256 KB cap, `base64.b64decode(validate=False)` bounded, `gunicorn --timeout 30 --graceful-timeout 10`, `limit_request_line/fields` in `gunicorn_conf.py`, per-IP `100/min` rate limit |
| MITM / interception | Activation traffic | Proxy exposed to LAN/internet, `block_global=false` | Traffic hijack, credential capture | `mitmproxy` binds `127.0.0.1` only in `docker-compose`, `MITMPROXY_WEB_PASSWORD` required via `.env`, `web_password` set, no TSS redirect by default (`gs.apple.com` passes through) |
| TLS pinning / downgrade | Device↔Albert TLS | Self-signed `albert.local` cert, mixed `http`/`https` | Silent activation fail, downgrade to cleartext | Terminate TLS at proxy; `LOCAL_ALBERT_SCHEME` auto-detect (`http` behind `mitmproxy` TLS), document CA install via `http://mitm.it`, `certs/server.crt` not used for FairPlay (separate `fairplay.crt`) |
| Supply-chain drift | Dependencies | Pinned `cryptography 42.0.5` vs runtime `48.0.1` | Non-reproducible build, silent API break | `requirements.txt` pinned to tested `cryptography==48.0.1`, `pyOpenSSL==26.2.0`, `mitmproxy==12.2.3`, `pymobiledevice3==11.19.4`, `gunicorn==21.2.0`, `pip-tools` hash, `Dockerfile FROM python:3.14-slim` matching venv `3.14` |
| Privilege escalation (container) | Docker | `root` user, `readOnlyRootFilesystem` false | Container break-out | `useradd app` + `USER app`, `read_only: true`, `tmpfs: /tmp`, `cap_drop: ALL`, `no-new-privileges:true`, resource `limits: 512M/1.0 CPU`, `tini` as PID 1 |
| Information disclosure | Logs/metrics | UDID/IMEI/serial in plaintext logs, `/metrics` unauth | Device fingerprinting | Structured JSON logs with `X-Request-ID`, UDID suffix-only redaction, `AccountToken` fields validated (`IMEI 15 digits`, `UDID 40 hex` or `00008020-…`), `/metrics` behind same bind (no external expose) |
| Persistence loss | Activation history | `activation_records = {}` in-memory | Lost audit after reboot | SQLite `logs/activations.db` (WAL), `GET /admin/activations` auth-gated (future), `logs/` volume in compose |

Out of scope: jailbreak/checkm8 exploitation, radio-baseband TSS, `MobileActivationService` SHA256 migration.

## TLS

- **Device → mitmproxy**: TLS intercepted by `mitmproxy` CA. Install the CA on the device via `http://mitm.it` after pointing Wi-Fi proxy to `host:18090`. Pin violations are expected for `A12+` on iOS 18; document that real activation may require `session` mode via `drmHandshake` or passing through `gs.apple.com` (TSS).
- **mitmproxy → Albert**: Plain `http` to `LOCAL_ALBERT_HOST:LOCAL_ALBERT_PORT` (`127.0.0.1:18090` / `albert-server:18090` in compose). Controlled by `LOCAL_ALBERT_SCHEME` (`http` default). Do not enable `https` between proxy and Albert unless you terminate with a trusted inner CA; otherwise set `LOCAL_ALBERT_SCHEME=http` and let `mitmproxy` present TLS externally.
- **`albert_server` inner TLS**: `certs/server.crt` / `server.key` are **not** FairPlay; they are only for `start.sh dev` HTTPS (`18443`) when debugging. Production `gunicorn` serves `http` behind the proxy/reverse-proxy. Rotate `server.crt` with `openssl req -x509 -newkey rsa:2048 -days 365 -subj "/CN=albert.local"` and `chmod 600 server.key`.
- **Cipher posture**: Relies on host `libssl`/`cryptography 48.0.1` defaults (TLS 1.2+). No custom cipher string. Verify with `openssl s_client -connect 127.0.0.1:18090` (should fail — no TLS there) vs `curl -k https://127.0.0.1:18443/health` in dev mode.
- **HSTS / headers**: `Cache-Control: private, no-cache, no-store, must-revalidate, max-age=0` on activation responses; `X-Request-ID` echoed; `ARS` header is SHA1 per Apple spec (not general hashing) — flagged `# nosec B303/B324` with comment.

## Key Management (0600)

- **FairPlay**: On first boot `albert_server.AlbertServer` generates `rsa 2048` (`public_exponent 65537`) and a self-signed CA (`CN=Apple iPhone Device CA`, `BasicConstraints ca=True`, `SHA256`, 5 years) and persists to:
  - `certs/fairplay.key` — `0600`, `TraditionalOpenSSL`, no encryption
  - `certs/fairplay.crt` — `0600`, PEM
  On subsequent boots the key is **loaded** if present; restart does not invalidate `DeviceCertificate`s.
- **Rotation**: `rm certs/fairplay.key certs/fairplay.crt && ./start.sh restart` or `python albert_server.py --rotate-fairplay` (if implemented). Back up `certs/` before rotation (`tar czf certs-backup-$(date +%F).tgz certs/`).
- **Server TLS** (non-FairPlay): `certs/server.key` must be `0600` (`ls -l certs/` should show `-rw-------`). `certs/server.crt` may be `0644`. Enforced in `setup.sh` and checked by `bandit`.
- **Secrets in repo**: Never commit `*.key`, `*.crt`, `*.pem`, `*.p12`, `.env`, `*.ipsw`, `*.shsh`, `activations.db`. `.gitignore` covers all; `scripts/sha256_manifest.sh` generates a `*.sha256` manifest **without** committing the IPSW.
- **File permissions CI**: `test -z "$(find certs -name '*.key' ! -perm 600 -print)"` and `git check-ignore` for `*.ipsw` are part of validation.

## Hardening Checklist (operator)

- [ ] `cp .env.example .env` and set `MITMPROXY_WEB_PASSWORD`, `ALBERT_ACCEPT_RISK=1`
- [ ] `chmod 600 certs/*.key certs/fairplay.crt` (verify with `ls -l certs/`)
- [ ] `ALBERT_HTTP_PORT=18090` consistent in `start.sh`, `gunicorn_conf.py`, `docker-compose.yml`, `firmware_restore_proxy.py`, `README`, `docs/RUNBOOK.md`, `docs/ARCHITECTURE.md`
- [ ] `curl http://127.0.0.1:18090/health` → `200` and `curl http://127.0.0.1:18090/ready` → `200` (FairPlay loaded)
- [ ] `curl http://127.0.0.1:18090/metrics` exposes `albert_up` (guard in prod firewall)
- [ ] Proxy web UI is `127.0.0.1:8081` with password, proxy port `127.0.0.1:8082`
- [ ] `docker compose config` shows `read_only: true`, `cap_drop: ALL`, `user: app`, no `version:` key
- [ ] `scripts/sha256_manifest.sh` produced `*.ipsw.sha256` and `git status` does not show `*.ipsw` as untracked

## Reporting a Vulnerability

Email the maintainer listed in `LICENSE`/`NOTICE` with `Subject: [SECURITY] albert_server`. Include reproduction, affected version/commit, and impact. Do not open a public issue for unpatched key-material or RCE. Expect acknowledgement within 72 h. If you can, propose a minimal patch and note whether `ALBERT_ACCEPT_RISK` or TLS is involved.

## References

- `docs/PRODUCTION_GAP_ANALYSIS.md` — gap analysis this policy closes (`P0-1`..`P0-5`, `P1-6`/`P1-7`, `P2`)
- `docs/RUNBOOK.md` — health/ready, start (host vs docker), rotation, troubleshooting
- `docs/ARCHITECTURE.md` — diagram with fixed `18090` ports and TLS termination
- `.env.example` — 12-factor env with `ALBERT_ACCEPT_RISK` gate
- `gunicorn_conf.py`, `Dockerfile`, `docker-compose.yml` — prod entrypoints
