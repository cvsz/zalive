# CI Failure Modes

Use this playbook when CI is red, flaky, blocked, or inconsistent with local results.

## Classification

Classify the failing job before editing code:

- deterministic code/test regression
- lint/type/format failure
- dependency or lockfile drift
- container/image build failure
- workflow syntax/configuration
- permissions/OIDC/secrets availability
- service dependency or test fixture failure
- runner/environment failure
- external provider outage/rate limit
- nondeterministic or race-related test

## Recovery sequence

1. Record exact workflow, job, step, head SHA, and failure message.
2. Inspect surrounding log context and annotations.
3. Reproduce locally or in an equivalent environment where practical.
4. Identify root cause before changing workflow policy.
5. Apply the smallest safe fix.
6. Add regression coverage where appropriate.
7. Run targeted validation first.
8. Run broader validation proportional to risk.
9. Re-check exact-head CI.

## Common anti-patterns

Do not:

- delete a failing test merely to get green CI
- mark required checks `continue-on-error` without a documented reason
- disable CodeQL, dependency review, secret scanning, or branch protection
- broaden permissions to `write-all`
- hardcode missing secrets
- retry indefinitely when inputs have not changed
- label a test flaky from one failure

## Evidence template

Record:

- workflow/run ID
- job/step
- head SHA
- failure class
- root cause
- files changed
- targeted validation
- full validation
- remaining uncertainty

Apply the central evidence-state definitions in `../../../ZEAZ-INTRODUCTION.md`. If verification cannot proceed because an unavailable secret, protected environment, missing hosted permission, external outage, or other concrete prerequisite prevents it, use `BLOCKED`. If the check simply has not been run or sufficient evidence has not been collected and no concrete blocker prevents execution, use `UNVERIFIED`. Never fabricate success.
