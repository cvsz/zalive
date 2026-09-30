# Repository Production Readiness

Assess each applicable gate as `VERIFIED`, `PARTIALLY VERIFIED`, `UNVERIFIED`, `BLOCKED`, or `NOT APPLICABLE`.

Review build/reproducibility, testing, security, data/migrations, backup/restore/RPO/RTO, CI/CD, deployment/rollback, runtime reliability, observability, runbooks, ownership and incident response.

## Readiness evidence vs risk acceptance

Readiness state and release authorization are separate decisions.

- A gate is `VERIFIED` only when direct evidence supports that exact claim.
- Apply the central evidence-state definitions in `../../../ZEAZ-INTRODUCTION.md`. Missing evidence without a preventing blocker is `UNVERIFIED`; a concrete preventing prerequisite is `BLOCKED`; evidence covering only part of the gate is `PARTIALLY VERIFIED`.
- An authorized owner may explicitly accept a known risk and still decide to release, but that acceptance does **not** change the readiness evidence state.
- Record accepted risk separately with owner, scope, rationale, expiry/review date, mitigation, and rollback/containment plan.
- Never convert an accepted risk into `VERIFIED`, `PARTIALLY VERIFIED`, or a production-ready claim without new evidence.

Do not declare production readiness unless every applicable readiness gate is `VERIFIED`; `NOT APPLICABLE` is acceptable only when applicability is explicitly justified. Readiness gates are independent of P0/P1/P2/P3 work-priority labels. `PARTIALLY VERIFIED`, `UNVERIFIED`, and `BLOCKED` all prevent a production-ready claim. A green build alone is insufficient.

## Release decision record

If a release proceeds with accepted risk, report both dimensions explicitly:

- **Readiness evidence:** current gate states
- **Release decision:** approved / not approved
- **Accepted risks:** separate list with accountable owner and conditions

A release may be authorized despite known risk, but the system must still be described using its actual evidence-backed readiness state.
