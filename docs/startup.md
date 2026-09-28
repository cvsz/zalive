# Start a project from ztemplate

This repository is a language-agnostic governance and tooling baseline, not a deployable product. Use GitHub **Use this template** (not a fork), clone the generated repository and start on a feature branch.

## 1. Initialize project identity

Requires Python 3.10+ and Git. Run first without --apply to preview exactly which four files will be updated:

    python3 scripts/bootstrap.py --name my-service --owner my-org --codeowner my-org/maintainers --description 'Describe the product'

Apply explicitly:

    python3 scripts/bootstrap.py --name my-service --owner my-org --codeowner my-org/maintainers --description 'Describe the product' --apply

The command creates .ztemplate-initialized.json and edits only README.md, ABOUT.md, .github/CODEOWNERS, and .github/ISSUE_TEMPLATE/config.yml. CODEOWNERS must be an actual GitHub user or org/team with write access; repository owner alone is not sufficient for an organization. Running again with identical arguments is a no-op; using different settings requires manual review. Run in a clean, new repository and review git diff before committing. If interrupted, inspect git diff and reset or repair manually before rerunning; changes are atomic per file but not a multi-file transaction.

## 2. Required manual decisions

- Choose language, runtime, framework, package manager, supported versions, repository visibility and release policy. See [profiles](profiles.md).
- Review LICENSE; the template's existing attribution remains intact. Select a project license and confirm copyright ownership with the legal owner.
- Replace or remove the placeholder Dockerfile and Makefile stack-specific commands. Do not ship a placeholder container.
- Set actual maintainers and protected ownership paths in CODEOWNERS. Confirm referenced users or teams have write access.
- Configure SECURITY.md's private reporting channel and verify the issue-form link after repository rename or transfer.
- Decide authentication, authorization, data retention, backups, error budgets, budget and operational responsibilities where applicable.
- Configure branch rulesets, required checks, signed commits if appropriate, protected deployment environments and least-privilege secrets.
- Ensure the template's GitHub Actions versions and feature availability are supported in the generated repository; add stack-specific checks without dropping baseline security checks.

## 3. Development baseline

Copy .env.example to a local .env; it must stay untracked. Add real code, automated tests, development commands and an integration test for your chosen runtime. The provided Makefile's app-specific targets fail until implemented to prevent false success. Run python3 -m unittest discover -s tests -v to validate the template bootstrap itself.

## 4. Operations and release evidence

Complete [architecture](architecture.md), [development](development.md), [release](release.md), and [implementation checklist](../IMPLEMENTATION-CHECKLIST.md). Establish staging deployment, synthetic health checks, structured logs, metrics, backups and isolated restore drills, rollback to a known-good build, alert routing, security response contacts, and release approval appropriate to the product's risk. Validate from a fresh clone and keep timestamped evidence. A green template CI is not proof of application production readiness.

## 5. Public hostnames

Follow [central Cloudflare/DNS ownership contract](cloudflare-terraform.md). Never introduce public DNS or shared tunnel changes from a generated application repository if a designated infrastructure repository owns them.
