# Cost and Token Budget

AI-agent workflows must be useful without creating unbounded cost or token consumption.

## Default controls

- Start with targeted repository discovery instead of whole-history scans.
- Reuse fresh evidence already collected in the same execution.
- Prefer targeted tests before full suites; run broader validation when risk warrants it.
- Avoid repeated retries when the underlying input or dependency has not changed.
- Cap autonomous work to the agreed acceptance criteria.
- Do not provision paid infrastructure, increase service tiers, or enable billable external services without authorization.
- For long-running analysis, checkpoint evidence so later agents can resume rather than repeat work.

## Escalate before cost expansion

Report expected impact before:
- creating new paid infrastructure
- materially increasing hosted CI usage
- adding high-cost model/evaluator loops
- running large load/soak tests against billable environments
- introducing recurring third-party services

Cost optimization must not weaken security, reliability, recovery, or required validation.
