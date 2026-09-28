# Repository Template Inventory

This repository provides a secure, reusable baseline for new GitHub projects.

## Governance and community
- AGENTS.md
- README.md
- ABOUT.md
- CONTRIBUTING.md
- CODE_OF_CONDUCT.md
- GOVERNANCE.md
- SECURITY.md
- .github/SUPPORT.md
- issue forms and pull request template
- CODEOWNERS

## Agent review
- AGENTS.md agent contract
- .agents/skills/scrutinize/SKILL.md (intent-first, end-to-end evidence-based review)

## Automation and security
- baseline CI
- CodeQL and CodeQL configuration
- dependency review
- Dependabot
- release notes configuration
- least-privilege workflow guidance

## Engineering lifecycle
- CHANGELOG.md
- ROADMAP.md
- IMPLEMENTATION-CHECKLIST.md
- architecture, development, release, and ADR documentation
- Cloudflare and Terraform ownership contract (`docs/cloudflare-terraform.md`)
- Dockerfile, Makefile, environment example, EditorConfig, Git attributes, and Git ignore baseline

## Project initialization
- scripts/bootstrap.py (stdlib-only, explicit --apply, allowlisted files, idempotent marker)
- tests/test_bootstrap.py and CI test integration
- templates/project-readme.md and templates/project-about.md
- docs/startup.md and docs/profiles.md
- Makefile app targets fail until customized rather than reporting false success

## Adoption checklist
After creating a repository from this template, replace project placeholders, review CODEOWNERS and security contacts, select the actual language/runtime CI matrix, configure required branch/ruleset checks, configure only required secrets/environments, and remove optional files that the project intentionally does not use.

Never copy production credentials into a generated repository.

## UI templates — zAlive Albert (albert_server.py) — AdminLTE 4 premium (https://github.com/topics/dashboard-template #1)
All 9 pages share `data-bs-theme="dark"` + `bootstrap@5.3.3` + `admin-lte@4.0.0` + `bootstrap-icons` via CDN, `app-wrapper > app-header (zAlive logo) > app-sidebar (Dashboard/Firmware/Admin/Health/Ready/Metrics/Validate) > app-main > app-footer`, `zalive-card #151a21` `zalive-border #232b36` `accent #3b82f6`, live via `0.0.0.0:18090` + `192.168.1.123:18090`, also in `templates/` for GitHub Pages:
- `templates/dashboard.html` — `GET /dashboard` premium dark UI (zAlive logo #3b82f6→#06b6d4, health pills `live·ready`, metrics activations/failures/up/rate, iPhone identity redacted, USB `05ac` check, IPSW `8.7GB sha256 b304…`, SQLite `267 rows` WAL, rate-limit + logs tail). `albert_server.py:DASHBOARD_HTML`.
- `templates/firmware.html` — `GET /firmware` curated 13 iPhone 5→15 Pro (A6→A16), `api.ipsw.me` live 1h + local `*.ipsw` overlay, table Version|Build|Released|Size|Signed|Local|Download, filter `select#product` dark `option {bg:#1a212e;color:#e5e7eb}`.
- `templates/admin.html` — `GET /admin` gated `ALBERT_ADMIN_TOKEN` `X-Admin-Token`, actions: clear cache, reset rate, DB checkpoint 10k/30d, purge >30d, recent activations, logs tail.
- `templates/health.html` — `GET /health` liveness `{"status":"ok","server":"albert-local","version":"1.1-fixed"}` → HTML with 3 cards Server/Version/Uptime + mTLS `enabled` · JSON via `?format=json` or `Accept: text/html` negotiation.
- `templates/ready.html` — `GET /ready` readiness `{"status":"ready","fairplay_loaded":true,"notAfter":"2031-09-27",days:1824}` → HTML with FairPlay/mTLS/Status cards + expiry warning, `?format=json` JSON.
- `templates/metrics.html` — `GET /metrics` Prometheus `albert_up 1` `albert_activation_total 267` → HTML with Up/Activations/Failures cards + `<pre>` exposition, `?format=prom` raw.
- `templates/validate.html` — `GET /api/validate` `{"ok":true,"checks":{ipsw,fairplay,db,env,api,logs}}` → HTML with 6 cards `✓ ok` + raw JSON, `?format=json` JSON.
- `templates/index.html` — `GET /` `{"service":"albert-local","endpoints":[...]}` → HTML with Quick links/Health/Device + endpoint buttons, `?format=json` JSON.
- `templates/404.html` — `GET /nonexistent → 404` zAlive `∅` card, links Dashboard/Firmware/Admin/Health, `@app.errorhandler(404)` JSON for `/api/*`.
- `static/zalive-logo.svg` (140×36) + `static/zalive-icon.svg` (32×32) + `static/favicon.svg` — wordmark `zAlive` ALBERT·FIRMWARE·RESTORE.

