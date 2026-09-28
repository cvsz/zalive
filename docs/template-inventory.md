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

## UI templates — zAlive Albert (albert_server.py)
- `templates/dashboard.html` — premium dark UI for `GET /dashboard` (zAlive logo #3b82f6→#06b6d4, health pills, metrics, iPhone XR identity, USB/idevice_id, IPSW SHA256, SQLite activations WAL, rate-limit + logs tail). Extracted from `albert_server.py:DASHBOARD_HTML`, also served via Flask `static/` (see `albert_server.py:1670` `Cache-Control public,max-age=3600`).
- `templates/firmware.html` — `GET /firmware` curated 13 devices iPhone 5→15 Pro (A6→A16), `api.ipsw.me` live cache 1h + local `*.ipsw` overlay, Version|Build|Released|Size|Signed|Local|Download, filter by Version/Build, `select#product` dark premium `option {bg:#1a212e;color:#e5e7eb}` fix.
- `templates/admin.html` — `GET /admin` gated by `ALBERT_ADMIN_TOKEN` (X-Admin-Token), controls: clear firmware cache, reset rate limits, DB checkpoint/prune 10k/30d, purge >30d, recent activations, logs tail.
- `templates/404.html` — branded 404 (`GET /nonexistent → 404`) zAlive dark card, `∅` mark, links to Dashboard/Firmware/Admin/Health, mirrors `albert_server.py:NOTFOUND_HTML` + `@app.errorhandler(404)` JSON for `/api/*`.
- `static/zalive-logo.svg` (140×36) + `static/zalive-icon.svg` (32×32) + `static/favicon.svg` — wordmark `zAlive` ALBERT·FIRMWARE·RESTORE, used in all dashboards.

