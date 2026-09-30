# Repository Baseline Rollout

Use this process to adopt the current `ztemplate` repository-foundation baseline in an existing repository.

## Rule

**Audit first. Port missing controls only. Never overwrite established project policy wholesale.**

Existing repositories may already have stricter or stack-specific:

- AGENTS/instruction contracts
- CI pipelines
- security tooling
- release workflows
- CODEOWNERS
- deployment/environment controls
- architecture and operational runbooks

Preserve those unless there is direct evidence that they need correction.

## Recommended waves

Prioritize repositories with production traffic, multi-tenant/customer data, security functions, payment/wallet responsibilities, deployment control surfaces, or high automation privileges.

Defer or handle separately:

- archived repositories
- upstream forks/mirrors
- vendor snapshots
- sample/tutorial repositories
- repositories whose upstream compatibility would be harmed by broad template files

## Per-repository workflow

1. Inspect the exact default branch/head.
2. Read existing `AGENTS.md`, README, SECURITY, CONTRIBUTING, CI, release, and infrastructure docs.
3. Inventory existing governance/security controls.
4. Compare with the current template baseline.
5. Classify missing controls by evidence state and priority.
6. Port only compatible missing controls.
7. Preserve project-specific check names and workflows.
8. Pin Actions safely without changing behavior.
9. Add/align repository validation where useful.
10. Add GitHub administration verification using project-specific required check names.
11. Open a focused pull request.
12. Run exact-head validation.
13. Merge only after required checks/review succeed.
14. Apply/verify GitHub administration controls with an authorized admin identity.
15. Record any remaining application production-readiness gates separately.

## Typical controls to port

Depending on what the target already has:

- canonical evidence-state semantics
- agent safety/authorization precedence
- cross-harness guidance
- `scripts/validate_repo.py`
- `scripts/github_admin.py`
- immutable Action pins
- CODEOWNERS coverage
- branch/review/check enforcement
- private vulnerability reporting
- Dependabot/security updates
- secret scanning/push protection
- least-privilege Actions defaults
- repository-production-readiness playbook
- CI failure/recovery guidance
- cost/token discipline for autonomous agents

## Do not copy blindly

Do not automatically replace:

- root `AGENTS.md`
- application Dockerfile/Makefile
- application CI matrices
- deployment workflows
- CODEOWNERS teams
- SECURITY contacts
- release/publishing credentials
- infrastructure ownership
- project license
- runtime/framework config

## Evidence

A rollout PR being merged proves only the repository changes that were merged.

It does not prove:

- production deployment
- application security
- backup/restore
- rollback
- observability
- performance/capacity
- incident response
- provider/API permissions
- compliance

Those gates remain project-specific.
