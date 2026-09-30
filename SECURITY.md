# Security Policy

Security is part of the default delivery baseline for `albert_server` (local Albert `albert.apple.com` emulator + `firmware_restore_proxy.py` mitmproxy interceptor).

## Reporting a vulnerability

Do not disclose exploitable vulnerabilities in public issues, pull requests, discussions, or commit messages. Use GitHub's private vulnerability reporting / security advisory capability when enabled for the repository, or contact the repository owner (`@cvsz`) through an agreed private channel (see `SUPPORT.md`, `GOVERNANCE.md`).

Include affected versions or commits, reproduction details, impact, prerequisites, and suggested remediation when available. Do not include credentials, private keys, production secrets, or personal data in the report — redact UDID/IMEI/Serial to the minimum needed.

This private-reporting policy is inherited from the template and retained for `albert_server`.

## Supported versions

`albert_server` tracks `main`. Security fixes are applied to `main` and the latest tagged release. Older tags and forks are not supported unless noted in `CHANGELOG.md` or a GitHub release. Python `3.14` (`python:3.14-slim` in `Dockerfile`) is the tested runtime; `3.9+` is the minimum per `README.md`.

## Threat model and scope

`albert_server` emulates Apple activation endpoints (`/deviceservices/drmHandshake`, `/deviceservices/deviceActivation`, `/WebObjects/ALUnbrick.woa/wa/deviceActivation`) and signs activation records with a local FairPlay key. The mitmproxy layer (`firmware_restore_proxy.py`) intercepts `albert.apple.com` only; `gs.apple.com` (TSS) is passed through to Apple. Trust boundaries are unauthenticated device activation payloads (`activation-info` plist + optional `DeviceCertRequest` CSR). `docs/PRODUCTION_GAP_ANALYSIS.md` and `NOTICE` document the full threat model.

Out of scope for this policy: Apple infrastructure, Apple-copyrighted IPSW files (only a SHA256 manifest is stored; `*.ipsw` is gitignored), and carrier/cloud entitlements.

## Key management (0600)

- **FairPlay key material** is persisted at `certs/fairplay.key` and `certs/fairplay.crt` with `0600` (`0o600`). On first start `albert_server.py` generates RSA 2048 + self-signed CA; on subsequent starts it loads the persisted files. Both files are `chmod 0o600` after write (`albert_server.py:952-956`, `FIRMWARE_CACHE` also `0o600`, `certs/server.key` is `0600` on current host; `certs/server.crt` is public `0644`).
- **Rotation:** `python albert_server.py --rotate-fairplay` removes `certs/fairplay.key` / `.crt` (also `rm certs/fairplay.* && ./start.sh restart` per `docs/RUNBOOK.md`) and regenerates on next start with `0600`.
- **Git hygiene:** `.gitignore` excludes `*.key`, `*.pem`, `*.crt`, `*.csr`, `*.p12`, `*.pfx`, `*.jks`, `*.keystore`, `*.srl`, `.env`, `*.log`, `logs/*`, `*.ipsw`, `*.im4p`, `*.trustcache`, `*.mtree`, `*.aea`, `*.shsh`, `firmware/`, `shsh/`, `*.db`, `*.sqlite*`, `.mitmproxy/`; `certs/*.key` and device identifiers are never committed. `logs/restore/` keeps only its `README.md` — re-opening the folder is paired with a blanket `logs/restore/*` so a newly added file type stays ignored by default. `IMPLEMENTATION-CHECKLIST.md` records no secrets committed.
- Operators are responsible for securing key material and complying with cryptography export controls (see `NOTICE`).

Do not commit or paste key material, `.env` values, or device identifiers.

## Request hardening and error contract

Production hardening is enforced in `albert_server.py`:

- **Request size limit:** `app.config['MAX_CONTENT_LENGTH'] = 512 * 1024` (env `ALBERT_MAX_CONTENT_LENGTH`, default `512KB`). Oversize requests return `413` JSON `{ "error": "payload too large", "limit": 524288, "request_id": "..." }` (`RequestEntityTooLarge` handler and explicit `413` handlers).
- **Validation `400`:** Malformed plist / `activation-info` returns `400` (`Empty request`, `Invalid plist`, `Missing activation-info`, `Unsupported content type`, `Invalid activation-info: expected dict`). Field validation for `IMEI` (15 digits), `UDID` (`40` hex or `00008020-` + 16 hex), `SerialNumber` (alphanumeric) returns `400` JSON `{ "error": "validation failed", "details": [...], "request_id": "..." }`.
- **Rate limiting `429`:** Per-IP `100/min` (`_RATE_LIMIT_MAX`) + per-UDID `10/min` (`ALBERT_RATE_LIMIT_PER_UDID`, default 10) over a `60s` window. Distributed via Redis `INCR+EXPIRE` when `ALBERT_REDIS_URL`/`REDIS_URL` is set, otherwise in-memory. Exceeded requests return `429` JSON `{ "error": "rate limit exceeded", "request_id": "..." }` with `X-RateLimit-Remaining` (and `X-RateLimit-Remaining` per-IP/UDID) and `X-Request-ID`. `before_request` applies the limit to `/deviceservices/*` and `/WebObjects/*`; `after_request` propagates `X-Request-ID` and `X-RateLimit-Remaining`.
- **Request tracing:** Every request gets `X-Request-ID` (incoming header or generated UUID `g.request_id`); structured JSON logging includes `request_id`/`remote_addr` with UDID redaction.
- **OPTIONS:** `/deviceservices/*` and `/WebObjects/*` return `204` with `Allow: GET, POST, OPTIONS`.

See also `gunicorn_conf.py` timeout (`30s`) and `docs/RUNBOOK.md` readiness checks.

## Risk gate — `ALBERT_ACCEPT_RISK`

Operation requires explicit acknowledgement of legal risk (see `NOTICE` Apple ToS disclaimer; use only on devices you own or have permission to test).

- Startup refuses with `exit 2` and `ERROR: ALBERT_ACCEPT_RISK must be 1 …` unless `ALBERT_ACCEPT_RISK=1` is set in the environment / `.env`, or `--allow-no-risk` is passed (lab-only, bypass is still logged), or `--rotate-fairplay` is used.
- When `ALBERT_ACCEPT_RISK=1`, the server logs `ALBERT_ACCEPT_RISK=1 acknowledged — activation bypass enabled (owned devices only, see NOTICE)`.
- Configure via `.env.example` / `docs/RUNBOOK.md` / `docs/ARCHITECTURE.md` (`ALBERT_HTTP_PORT=18090`, `FAIRPLAY_KEY_PATH`, `ALBERT_MODE`).

No bypass or activation record is issued without that gate.

## Automation already present

Do not add duplicates — the following are already committed:

- **Dependabot** (`.github/dependabot.yml`): weekly updates for `github-actions` and `docker` (`open-pull-requests-limit: 10`).
- **CodeQL** (`.github/workflows/codeql.yml` + `.github/codeql-config.yml`): `security-extended` queries; workflow `Analyze GitHub Actions` (`actions` language) on `push`/`pull_request` to `main` and weekly schedule `23 3 * * 1` with `security-events: write`.
- **Dependency Review** (`.github/workflows/dependency-review.yml`): on `pull_request` to `main`.
- **CI** (`.github/workflows/ci.yml`): `ruff check`, `bandit -r . --exclude ./venv`, `pytest -q`, `docker compose config` on `push`/`pull_request` (`**`, Python `3.14`).

Keep these workflows enabled and review Dependabot alerts.

## TLS and proxy

TLS is terminated at mitmproxy; the local Albert is reached via `LOCAL_ALBERT_SCHEME` (usually `http` behind the proxy). Install the mitmproxy CA via `http://mitm.it` on the iOS device and configure Wi-Fi proxy or `iproxy` per `README.md` / `docs/RUNBOOK.md`. `certs/server.crt` / `server.key` provide the local TLS endpoint when run standalone.

## Security expectations

- Keep dependencies patched and review Dependabot alerts.
- Keep CodeQL and dependency-review workflows enabled when supported.
- Use least-privilege GitHub Actions permissions (`contents: read`, `security-events: write` where needed).
- Never commit credentials, tokens, private keys, production secrets, or sensitive personal data.
- Validate untrusted input and enforce authorization at trust boundaries.
- Prefer fail-closed behavior for security-sensitive paths (validation `400`, size `413`, rate limit `429`).
- Preserve tenant and data isolation where applicable; redact UDID/IMEI in logs.
- Review third-party actions and pin or constrain them according to project policy.
- Do not disable security gates merely to obtain a passing build.

## Incident handling

For `albert_server`, document containment (stop `albert_server`/`mitmproxy`, rotate `certs/fairplay.*` if key compromise is suspected), remediation (patch, re-issue activation records), validation (`/health` `200`, `/ready` `200` with `fairplay_loaded`, `pytest`/`ruff`/`bandit`/`docker compose config`), disclosure via the private reporting channel above, and rollback (`git` tags `429fff8…`, `*.bak` not committed, `logs/activations.db` WAL retained) appropriate to the risk profile.
