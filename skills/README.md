# ZEAZ Skills Catalog

This directory is the canonical source of truth for reusable ZEAZ skills.

Each skill lives in one top-level directory:

```text
skills/<skill-name>/SKILL.md
```

## Design rules

- One skill per directory.
- Keep skill content harness-neutral where practical.
- Put harness-specific packaging in generated adapters or plugin surfaces, not in the canonical skill.
- Prefer discovery-first loading instead of preloading the entire catalog into every agent session.
- Preserve the repository evidence-state and authorization rules from `ZEAZ-INTRODUCTION.md`.
- Do not vendor third-party skill content unless its license, attribution, update strategy, and security review are explicit.

## Minimum skill metadata

Recommended frontmatter:

```yaml
---
name: zeaz-example
title: ZEAZ Example
description: Short routing description.
version: "0.1.0"
license: MIT
tags: [example]
supported_harnesses: [codex, claude, opencode]
risk_level: low
requires_network: false
requires_credentials: false
evidence_required: true
---
```

Additional fields may be added when a skill requires them, but core semantics should remain stable.

## Lifecycle

1. Add or update a canonical skill under `skills/`.
2. Register it through a component manifest when it belongs to a reusable component.
3. Run catalog validation/generation before publishing harness-specific packages.
4. Keep generated plugin/marketplace files reproducible from source manifests.
5. Record version and validation evidence before release.
