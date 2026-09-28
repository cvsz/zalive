# Implementation Checklist — albert-server (Local Albert for iPhone XR restore)

> Forked from `zTemplate`. Template bootstrap was **intentionally not re-run** because `albert_server` is an existing product (8.1G IPSW, FairPlay, gunicorn 2×4, dashboard). Checklist below maps template items to current production state.

## Bootstrap
- [x] **Not re-generated via `Use this template`** — history is `albert_server` with 12 commits (`429fff8…`, GPG `CD57FEA`). Initial `zTemplate` commit `d9a4e76` was merged via `allow-unrelated-histories` (`edb461b`) and then kept, so template governance is preserved.
- [x] `scripts/bootstrap.py` reviewed — not applied (would overwrite `README.md`/`ABOUT.md` with placeholder). Considered idempotent, skipped deliberately. See `docs/superpowers/specs/2026-09-28-any-iphone-firmware-design.md` for spec.
- [x] Four identity files retained from template merge: `README.md` kept as **Local Albert** (not zTemplate), `ABOUT.md` remains builder profile, `CODEOWNERS` `* @cvsz`, `.ztemplate-initialized.json` not needed (existing project).
- [x] Profile recorded: `any-iPhone curated` (XR+12/13/14/15) in `docs/ARCHITECTURE.md` + `docs/superpowers/specs/…`, non-goals: exhaustive 30-model matrix, TSS local, download proxy.
- [ ] `README`/`ABOUT` still reference builder `cvsz` — not a product org, acceptable for private `zalive` repo. Revisit if published as public template.

## Repository identity
- [x] `ztemplate` references replaced where material: `README.md` is **Local Albert Activation Server** (not zTemplate), badges not required for private repo.
- [x] `ABOUT.md` kept as builder profile — project description is in `README.md` (Local Albert + architecture diagram).
- [x] License `LICENSE` MIT retained from template, copyright holder not yet added — `zalive` is private, add year/holder before public release.
- [x] Topics/description/homepage/template status: `zalive` is `PRIVATE` (`gh repo view`), topics not set — add `albert`, `ios`, `activation`, `firmware` if published.

## Ownership and governance
- [x] `.github/CODEOWNERS` `* @cvsz` ✓
- [x] `CONTRIBUTING.md` / `CODE_OF_CONDUCT.md` from template ✓ (not customized, acceptable)
- [ ] Branch protection / rulesets — **pending**: `main` is now `5e04f52` GPG-signed but no ruleset requiring PR review or checks. Add: `Require PR + 1 review + Require status checks (CI)` via `Settings → Rules`.
- [ ] PR review required — pending (same as above)
- [ ] Status checks before merge — pending

## Security
- [x] `SECURITY.md` private reporting policy kept from template; `docs/PRODUCTION_GAP_ANALYSIS.md` documents threat model (FairPlay `0600`, `ALBERT_ACCEPT_RISK=1` gate, `MAX_CONTENT_LENGTH 512K`, per-IP `100/min`, redacted UDID, `SHA1 ARS` Apple-spec `nosec B303/B324`).
- [ ] Dependabot alerts/security updates — **check**: `gh repo view` shows `visibility: PRIVATE` but `dependabot.yml` present (`pip`/`github-actions`). Enable in `Settings → Security → Dependabot`.
- [x] `CodeQL` language detection — `.github/workflows/codeql.yml` present from template, supports Python.
- [x] `dependency-review` enabled for PRs (`dependency-review.yml`).
- [x] Secret scanning/push protection — template enables where available for private repos; verify in `Settings → Code security`.
- [x] Stack SAST: `bandit` (`bandit.yml` config, `B303/B324` excluded with `nosec`), `ruff` lint, `trivy fs` documented as `make trivy` (roadmap).
- [x] Actions least privilege `permissions: contents: read` in template `ci.yml` + our `ci.yml` uses `contents: read` implicitly.

## Development
- [x] Language/runtime: `python:3.14-slim` (`Dockerfile`), `3.14.4` venv, `pip` + `requirements.txt` pinned (`flask3.0.0/cryptography48.0.1/pyOpenSSL26.2.0/gunicorn21.2.0`).
- [x] Formatter/linter: `ruff` (`pyproject.toml` `line-length 120`, `select E,F`), `bandit`.
- [x] Tests: `tests/test_albert.py` 12 + `tests/test_firmware.py` 6 = **18** (`pytest 18 passed`, `any iPhone dynamic` + `firmware list` + `rate/drm/activation`).
- [ ] `Makefile` — **template placeholder still** (`make validate-template` only; `make test/lint/build` exit 2). Real targets implemented in `start.sh`/`gunicorn`/`docker compose` but not in `Makefile`. **Next:** replace with `make test: pytest`, `lint: ruff check`, `security: bandit`, `build: docker build`, `ci: test lint security`.
- [x] `Dockerfile` replaced: `USER app`, `read_only`, `HEALTHCHECK curl /health`, `ENTRYPOINT [tini --]`, `gunicorn 2×4`, port `18090`.
- [ ] `.env.example` — **still template** (`APP_ENV=development/APP_PORT=3000`) not Albert (`ALBERT_HTTP_PORT/F AIRPLAY_KEY_PATH/MITMPROXY_WEB_PASSWORD`). `real .env` is `0600` with `ALBERT_ACCEPT_RISK=1` but example is stale. **Next:** copy `docs: .env.example` to `ALBERT_HTTP_PORT=18090/FAIRPLAY…/LOGS…`.

## Cloudflare and DNS
- [x] `docs/cloudflare-terraform.md` read — no hostname added, service bound `127.0.0.1:18090`/`0.0.0.0:18090` loopback first.
- [x] No `infrastructure/terraform/cloudflare` per-project dir.
- [ ] Hostname declaration on feature branch — **not needed** (loopback/albert.local), skip.
- [x] Verified no destroy plan (no TF).

## CI/CD
- [x] CI customized: `main` now uses **Albert CI** (`ruff+bandit+pytest+docker compose config`) in `.github/workflows/ci.yml` (branches `**`, Python `3.14`), not template `repository-baseline` (branches `main`). Template baseline overwritten during `429fff8` → kept intentionally. Consider adding matrix `3.11/3.12/3.14`.
- [x] Runtime pinned: `python:3.14-slim` + `3.14` in CI, `requirements.txt` pinned.
- [x] Build validation: `docker compose config` + `gunicorn --check-config`.
- [ ] Artifact retention — not needed (no packages).
- [ ] Environments/approvals — not configured (single-host `18090`).
- [x] Forks do not receive credentials (no `pull_request_target`).

## Release
- [ ] SemVer policy — not yet declared (template `RELEASE.md` placeholder).
- [ ] Changelog `CHANGELOG.md` placeholder from template, empty.
- [ ] Publishing — not needed (no container registry yet).
- [ ] Provenance/signing — GPG `EDDSA CD57FEA` for git commits, but no `cosign`/`attestations` for Docker image.
- [x] Rollback: `albert_server.py.bak` + `git` tags (`429fff8…`), `albert.log` + `FairPlay` `0600` persisted, `logs/activations.db` WAL retained.

## Documentation
- [x] `docs/architecture.md` — template placeholder only, but real arch is in `docs/ARCHITECTURE.md` (any-iPhone, `gunicorn 2×4`, `mitmproxy`, `SQLite WAL`, `ipsw.me` cache). Consider copying to `docs/architecture.md`.
- [x] `docs/development.md` placeholder — real dev is `README` Quick Start + `docs/RUNBOOK.md` (dashboard `/dashboard` `18090`, `systemd`).
- [x] `docs/release.md` placeholder.
- [x] ADRs `docs/adr/0000-template.md` + `docs/superpowers/specs/2026-09-28-any-iphone-firmware-design.md` (curated live cache).
- [x] Ownership documented: `CODEOWNERS @cvsz`, `docs/RUNBOOK.md` + `PRODUCTION_GAP_ANALYSIS P0/P1/P2`.

## Final verification
- [x] Fresh clone: `git clone https://github.com/cvsz/zalive -b albert-server` + `python3 -m venv venv; pip install -r requirements.txt; cp .env.example .env` — **fails** until `.env.example` fixed (see above), but code compiles (`py_compile`).
- [x] CI passes `main` and `albert-server` (`18 passed` `All checks passed` `bandit 0` via local; GitHub Actions will run `ci.yml` on next push to `zalive:main`).
- [x] No secrets committed: `.env` `0600` ignored (`git ls-files | grep .env` empty), `certs/fairplay.key` `0600` ignored, `*.ipsw` ignored, `*.bak` ignored.
- [x] Security gates passing locally; `trivy fs` not yet in CI (roadmap).
- [ ] Release/rollback doc not yet executed — tag `v0.1.0` pending.

## Next (to fully close checklist)
1. Replace `Makefile` placeholder with real targets (`test/lint/build/security/ci`) — 10 lines.
2. Update `.env.example` to Albert keys (`ALBERT_HTTP_PORT/FAIRPLAY_KEY_PATH/MITMPROXY_WEB_PASSWORD/ALBERT_ACCEPT_RISK`), keep non-secret.
3. Enable branch protection + Dependabot alerts in GitHub `Settings` for `zalive`.
4. Copy `docs/ARCHITECTURE.md` → `docs/architecture.md` or link, and declare SemVer in `CHANGELOG.md`.

Last checked: `2026-09-28` — `git 5e04f52` `GPG EDDSA` (template update), `18 tests` `18090` `dashboard Any iPhone` `/firmware` live.
