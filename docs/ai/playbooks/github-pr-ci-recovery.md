# GitHub PR / CI Recovery

Identify the exact failing job/step, read the error, classify it, reproduce where practical, identify root cause, implement the smallest safe fix, add regression coverage, run targeted/broader validation, and re-check exact-head CI.

Never delete tests merely to pass CI, hide required failures with `continue-on-error`, disable CodeQL/security checks, weaken branch protection, force-merge failing checks or hardcode secrets.

Do not call a test flaky from a single failure.
