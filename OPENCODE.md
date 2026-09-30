# OPENCODE.md — ZEAZ OpenCode Operating Instructions

Read `AGENTS.md` first and use `ZEAZ-INTRODUCTION.md` as the shared execution framework.

## Working contract

- Inspect exact repository state before editing.
- Preserve unrelated local work.
- Follow repository-local architecture and conventions.
- Fix root causes using the smallest safe change.
- Keep security and authorization boundaries above task instructions.
- Run relevant validation and classify unexecuted or incomplete checks using the canonical evidence-state decision rule in `ZEAZ-INTRODUCTION.md`; use `BLOCKED` when a concrete prerequisite prevents verification.
- Never expose secrets.
- Do not bypass required checks or force-merge. Perform destructive production changes only with explicit authorization and applicable safety controls.
- Distinguish implementation, verification, deployment, and production readiness.
- Use the reusable playbooks under `docs/ai/` only when relevant to the task.

## Evidence states

Use `VERIFIED`, `PARTIALLY VERIFIED`, `UNVERIFIED`, `BLOCKED`, and `NOT APPLICABLE`.

## Cost discipline

Avoid unbounded retry/search loops and repeated unchanged scans. Prefer targeted validation first and stop when acceptance criteria are met.


## Repository administration

Use `scripts/github_admin.py` only when the task concerns GitHub repository controls. Dry-run is the default. Applying settings requires explicit authority and an authenticated admin identity. Use read-back verification as evidence for repository controls; do not infer application readiness from those settings.
