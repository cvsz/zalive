# Cross-Harness Compatibility

The repository may be used by multiple AI engineering hosts. The shared behavioral contract is defined by `AGENTS.md` and `ZEAZ-INTRODUCTION.md`.

## Supported instruction surfaces

| Harness | Primary repository instruction |
| --- | --- |
| Codex and AGENTS-compatible agents | `AGENTS.md` |
| Claude Code | `CLAUDE.md`, which defers to `AGENTS.md` |
| OpenCode | `OPENCODE.md`, which defers to `AGENTS.md` |
| Other compatible IDE/CLI agents | `AGENTS.md` plus task-specific `docs/ai/` playbooks |

## Compatibility invariants

All harness-specific files must preserve these invariants:

- safety and authorization boundaries outrank operator/task instructions
- repository-local rules are read before modification
- unrelated work is preserved
- secrets are never exposed
- security controls are not bypassed to obtain green CI
- evidence states use the single canonical definitions and decision rule in `ZEAZ-INTRODUCTION.md` across all harnesses
- implementation, verification, deployment, and production readiness remain distinct
- destructive or production-impacting changes require appropriate authorization

Harness-specific files should stay thin. Do not duplicate the entire framework into every adapter because duplicated policy drifts.

## Review checklist

When changing any harness-facing file:

1. Compare it with `AGENTS.md` and `ZEAZ-INTRODUCTION.md`.
2. Confirm no precedence inversion exists.
3. Confirm no harness grants broader destructive authority.
4. Confirm evidence-state semantics defer to the canonical definitions in `ZEAZ-INTRODUCTION.md` without local reinterpretation.
5. Confirm task playbook links remain valid.
