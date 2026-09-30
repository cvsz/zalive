# ZEAZ Skill Catalog Architecture

This repository adopts a catalog architecture inspired by mature multi-skill repositories while keeping ZEAZ content, licensing, and policy independent.

## Architecture

```text
skills/                 canonical skill source
components.d/           one-file-per-component catalog
plugins.d/              plugin source manifests
generated plugin trees  derived harness-specific packages
versions/benchmarks     optional release evidence as the catalog matures
```

## Invariants

1. `skills/` is the canonical content source.
2. Component and plugin manifests are metadata, not duplicated skill text.
3. Harness adapters must preserve the semantics in `ZEAZ-INTRODUCTION.md`.
4. Generated outputs must be reproducible from committed source manifests.
5. Third-party content must not be copied into this catalog without explicit license and provenance review.
6. Discovery-first routing is preferred to minimize context/token cost.
7. Skill installation or presence is not readiness evidence by itself.

## Why this structure

A monolithic catalog creates merge contention and makes ownership unclear. One-file-per-component manifests reduce conflicts and make review ownership explicit.

Keeping canonical skills separate from harness packaging reduces Claude/Codex/OpenCode drift and lets each harness receive the smallest compatible package.

A discovery-first finder avoids loading every skill into context and aligns with the repository's cost/token discipline.

## Future extension points

These are optional and should be added only when there is real content to validate:

- machine-readable generated skill catalog;
- version index;
- benchmark/reference-set evidence;
- marketplace manifests;
- schema validation for component/plugin manifests;
- generated harness packages;
- orphan detection and pruning with explicit safety limits.

Do not create empty benchmark or reference-set artifacts solely to improve an external readiness score.
