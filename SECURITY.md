# Security Policy

Security is part of the default delivery baseline for `albert_server` (local Albert `albert.apple.com` emulator + `firmware_restore_proxy.py` mitmproxy interceptor).

## Reporting a vulnerability

Do not disclose exploitable vulnerabilities in public issues, pull requests, discussions, or commit messages. Use GitHub's private vulnerability reporting / security advisory capability when enabled for the repository, or contact the repository owner (`@cvsz`) through an agreed private channel (see `.github/SUPPORT.md`, `GOVERNANCE.md`).

Include affected versions or commits, reproduction details, impact, prerequisites, and suggested remediation when available. Do not include credentials, private keys, production secrets, or personal data in the report — redact UDID/IMEI/Serial to the minimum needed.

This private-reporting policy is inherited from the template and retained for `albert_server`.

## Supported versions

`albert_server` tracks `main`. Security fixes are applied to `main` and the latest tagged release. Older tags and forks are not supported unless noted in `CHANGELOG.md` or a GitHub release. Python `3.14` (`python:3.14-slim` in `Dockerfile`, `python-version: "3.14"` in CI) is the tested runtime; no minimum is declared in `README.md` or `pyproject.toml`; CI only exercises 3.14.

Tested runtime: `python:3.14-slim` in `Dockerfile`, `python-version: "3.14"` in CI. No minimum Python version is declared in `README.md` or `pyproject.toml`, so only 3.14 is actually exercised.

## Threat model and scope

`albert_server` emulates Apple activation endpoints (`/deviceservices/drmHandshake`, `/deviceservices/deviceActivation`, `/WebObjects/ALUnbrick.woa/wa/deviceActivation`) and signs activation records with a local FairPlay key. The mitmproxy layer (`firmware_restore_proxy.py`) intercepts `albert.apple.com` only; `gs.apple.com` (TSS) is passed through to Apple. Trust boundaries are unauthenticated device activation payloads (`activation-info` plist + optional `DeviceCertRequest` CSR). `docs/PRODUCTION_GAP_ANALYSIS.md` and `NOTICE` document the full threat model.

Out of scope for this policy: Apple infrastructure, Apple-copyrighted IPSW files (only a SHA256 manifest is stored; `*.ipsw` is gitignored), and carrier/cloud entitlements.

## Key management (0600)

- **FairPlay key material** is persisted at `certs/fairplay.key` and `certs/fairplay.crt` with `0600` (`0o600`). On first start `albert_server.py` generates RSA 2048 + self-signed CA; on subsequent starts it loads the persisted files. Both files are `chmod 0o600` after write (`albert_server.py:952-956`, `FIRMWARE_CACHE` also `0o600`, `certs/server.key` is `0640` on current host; `certs/server.crt` is public `0644`).
- **Rotation:** `python albert_server.py --rotate-fairplay` removes `certs/fairplay.key` / `.crt` (also `rm certs/fairplay.* && ./start.sh restart` per `docs/RUNBOOK.md`) and regenerates on next start with `0600`.
- **Git hygiene:** `.gitignore` excludes `*.key`, `*.pem`, `*.crt`, `*.csr`, `*.p12`, `*.pfx`, `*.jks`, `*.keystore`, `*.srl`, `.env`, `*.log`, `logs/*`, `*.ipsw`, `*.im4p`, `*.trustcache`, `*.mtree`, `*.aea`, `*.shsh`, `firmware/`, `shsh/`, `*.db`, `*.sqlite*`, `.mitmproxy/`; `certs/*.key` and device identifiers are never committed. **Note:** this only covers new commits. A `git-filter-repo` pass on 2026-09-28 cleaned 20 commits, but identifiers re-entered in later commits and remain readable via `git show <commit>:<path>`; see the Git History row in `AUDIT-REPORT.md`. Use `git log -S<identifier>` to audit before assuming history is clean. `logs/restore/` keeps only its `README.md` — re-opening the folder is paired with a blanket `logs/restore/*` so a newly added file type stays ignored by default. `IMPLEMENTATION-CHECKLIST.md` records no secrets committed.
- Operators are responsible for securing key material and complying with cryptography export controls (see `NOTICE`).

Do not commit or paste key material, `.env` values, or device identifiers. The admin browser UI keeps its token in tab-scoped `sessionStorage`; dynamic device and upstream values are HTML-escaped before rendering. HTML responses use per-response CSP nonces for inline scripts, with `unsafe-inline` disabled for JavaScript.

## Request hardening and error contract

Production hardening is enforced in `albert_server.py`:

- **Request size limit:** `app.config['MAX_CONTENT_LENGTH'] = 512 * 1024` (env `ALBERT_MAX_CONTENT_LENGTH`, default `512KB`). Oversize requests return `413`. Device paths answer with a plist `{ "Error", "Details", "RequestID" }`; `/api/*` and browser routes keep JSON. Device endpoints must stay plist: iOS parses them as property lists and reports a JSON body as `NSCocoaErrorDomain 3840` ("Unexpected character {"), which masks the real failure. (`RequestEntityTooLarge` handler and explicit `413` handlers).
- **Validation `400`:** Malformed plist / `activation-info` returns `400` (`empty request`, `invalid plist`, `missing activation-info`, `unsupported content type`, `invalid activation-info: expected dict`) -- body shape as above. Field validation for `IMEI` (15 digits), `UDID` (`40` hex or `00008020-` + 16 hex), `SerialNumber` (alphanumeric) returns `400` with `Details` listing each rejected field (plist on device paths, JSON on `/api/*`).
- **Device-route authentication `401`:** `/deviceservices/*` and `/WebObjects/*` accept a constant-time checked `X-MTLS-Token` when `ALBERT_MTLS_TOKEN` is configured, or a TLS-verified client certificate when standalone mTLS is active. Certificate PEMs or marker strings in HTTP headers are never proof of identity. Compose requires a 32+ character token for Albert and firmware routes; outside Compose, keep the listeners loopback-only unless protected by TLS and authentication. Body is a plist for device routes.
- **Rate limiting `429`:** Per-IP `100/min` plus per-UDID `10/min` over a `60s` window. The default Gunicorn configuration uses one worker so in-memory limits are shared across its threads. More than one worker requires Redis and `ALBERT_REDIS_FAIL_CLOSED=1`; when Redis is unavailable the limiter rejects requests instead of silently falling back to per-worker counters. Device routes return plist errors. `before_request` applies limits to device and `/api/*` routes.
- **Request tracing:** Every request gets `X-Request-ID` (incoming header or generated UUID `g.request_id`); structured JSON logging includes `request_id`/`remote_addr` with UDID redaction.
- **OPTIONS:** `/deviceservices/*` and `/WebObjects/*` return `204` with `Allow: GET, POST, OPTIONS`.
- **Diagnostic detail is admin-only:** `/api/validate` answers without a token so a first-run setup can be checked before credentials exist, but returns one pass/fail line per check (`"detail": false`). Row counts, certificate dates, log paths and env var names need `X-Admin-Token`. No endpoint returns raw exception text; failures go to `logger.exception`.

See also `gunicorn_conf.py` timeout (`30s`) and `docs/RUNBOOK.md` readiness checks.

## Risk gate — `ALBERT_ACCEPT_RISK`

Operation requires explicit acknowledgement of legal risk (see `NOTICE` Apple ToS disclaimer; use only on devices you own or have permission to test).

- Startup refuses with `exit 2` and `ERROR: ALBERT_ACCEPT_RISK must be 1 …` unless `ALBERT_ACCEPT_RISK=1` is set in the environment / `.env`, or `--allow-no-risk` is passed (lab-only, bypass is still logged), or `--rotate-fairplay` is used.
- When `ALBERT_ACCEPT_RISK=1`, the server logs `ALBERT_ACCEPT_RISK=1 acknowledged — activation bypass enabled (owned devices only, see NOTICE)`.
- Configure via `.env.example` / `docs/RUNBOOK.md` / `docs/architecture.md` (`ALBERT_HTTP_PORT=18090`, `FAIRPLAY_KEY_PATH`, `ALBERT_MODE`).

No bypass or activation record is issued without that gate.

## Automation already present

Do not add duplicates — the following are already committed:

- **Dependabot** (`.github/dependabot.yml`): weekly updates for `github-actions` and `docker` (`open-pull-requests-limit: 10`).
- **CodeQL** (`.github/workflows/codeql.yml` + `.github/codeql-config.yml`): `security-extended` queries; workflow `Analyze GitHub Actions` (`actions` language) on `push`/`pull_request` to `main` and weekly schedule `23 3 * * 1` with `security-events: write`.
- **Dependency Review** (`.github/workflows/dependency-review.yml`): on `pull_request` to `main`.
- **CI** (`.github/workflows/ci.yml`): `ruff check`, `bandit -r . --exclude ./venv`, `pytest -q --ignore=tests/test_bootstrap.py`, `docker compose config` on `push`/`pull_request` (`**`, Python `3.14`).

Keep these workflows enabled and review Dependabot alerts.

## TLS and proxy

Device TLS is terminated at mitmproxy; the Compose proxy sends requests to Albert over the private Docker network with `ALBERT_MTLS_TOKEN` (at least 32 characters). Compose binds all published ports to loopback and refuses a non-loopback bind. Do not expose the plain-HTTP proxy or app directly to a LAN; use a TLS reverse proxy/VPN for remote access. Install the mitmproxy CA via `http://mitm.it` on the iOS device and configure Wi-Fi proxy or `iproxy` per `README.md` / `docs/RUNBOOK.md`. Standalone Albert can use `certs/server.crt` / `server.key` with a verified client CA and token. PEMs forwarded in HTTP headers are not accepted as client-authentication proof.

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
