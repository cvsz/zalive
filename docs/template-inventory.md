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
