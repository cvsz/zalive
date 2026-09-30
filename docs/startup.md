# Project Startup — Template Bootstrap

This document describes how to initialize a new repository from the `albert_server` template (or `zTemplate` upstream).

## Prerequisites

- GitHub account with repo creation permissions
- Python 3.13+ (for `scripts/bootstrap.py`)
- Write access to target GitHub org/user (for `--codeowner`)

## Quick Start

```bash
# 1. Create repo from template (GitHub UI: "Use this template")
# 2. Clone your new repo
git clone https://github.com/<owner>/<new-repo>
cd <new-repo>

# 3. Run bootstrap (dry-run first)
python3 scripts/bootstrap.py \
  --name <project-name> \
  --owner <github-owner> \
  --codeowner <github-owner>/<team> \
  --description "One-line project description"

# 4. Apply changes
python3 scripts/bootstrap.py \
  --name <project-name> \
  --owner <github-owner> \
  --codeowner <github-owner>/<team> \
  --description "One-line project description" \
  --apply

# 5. Verify
git diff --stat
git commit -am "chore: bootstrap <project-name>"
git push
```

## Bootstrap Parameters

| Flag | Required | Description |
|------|----------|-------------|
| `--name` | Yes | Repository name (alphanumeric, dash, underscore, dot) |
| `--owner` | Yes | GitHub user or organization |
| `--codeowner` | Yes | GitHub user/team with **write access** (e.g., `owner/team`) |
| `--description` | Yes | One-line, max 500 chars, no newlines |
| `--apply` | No | Write changes (omit for dry-run) |
| `--root` | No | Repository root (default: parent of script) |

## What Bootstrap Changes

| File | Change |
|------|--------|
| `README.md` | `{{PROJECT_NAME}}`, `{{DESCRIPTION}}`, `{{OWNER}}` |
| `ABOUT.md` | `{{PROJECT_NAME}}`, `{{DESCRIPTION}}` |
| `.github/CODEOWNERS` | `@cvsz` → `@<codeowner>` |
| `.github/ISSUE_TEMPLATE/config.yml` | Security URL → `https://github.com/<owner>/<name>/security` |
| `.ztemplate-initialized.json` | Marker with bootstrap args (prevents re-init with different args) |

## Post-Bootstrap Checklist

- [ ] Verify CODEOWNERS team has write access to repo
- [ ] Review `LICENSE` (preserve original attribution)
- [ ] Review `SECURITY.md` — update contacts if needed
- [ ] Configure GitHub branch protection (`main` branch)
- [ ] Enable Dependabot, CodeQL, Dependency Review (already in workflows)
- [ ] Set repository secrets for CI/CD if deploying
- [ ] Update `docker-compose.yml` placeholders for your deployment
- [ ] Run `make check` — all tests, lint, security must pass

## Re-initialization

To re-run with same settings (idempotent):
```bash
python3 scripts/bootstrap.py --apply --name <same> --owner <same> --codeowner <same> --description <same>
```

To change settings: **edit files manually** — bootstrap refuses conflicting re-init.

## Template Upstream

This template derives from `cvsz/zTemplate`. To sync upstream changes:
```bash
git remote add upstream https://github.com/cvsz/zTemplate
git fetch upstream
git merge upstream/main --allow-unrelated-histories
# Resolve conflicts, then test
make check
```

## Common Issues

| Error | Resolution |
|-------|------------|
| `Invalid CODEOWNERS` | Team must exist and have write access; use `owner/team` format |
| `Already initialized` | Delete `.ztemplate-initialized.json` or use same args |
| `Unsafe template file` | Symlinks not allowed; ensure template files are regular files |
| `Security URL mismatch` | Check `.github/ISSUE_TEMPLATE/config.yml` has expected URL |

## Support

- Template issues: https://github.com/cvsz/zTemplate/issues
- Project issues: `https://github.com/<owner>/<name>/issues`
- Security: See `SECURITY.md` (private reporting)