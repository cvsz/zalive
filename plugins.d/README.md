# Plugin Catalog Source

Use `plugins.d/*.yml` as source manifests for generated harness-specific plugin packages.

The canonical skill content remains under `skills/`. Generated plugin trees should reference or copy from that source rather than maintaining independent skill text.

## Goals

- prevent cross-harness content drift;
- keep Claude, Codex, OpenCode, Cursor, and future adapters reproducible;
- support discovery-first loading;
- make plugin metadata reviewable separately from skill behavior.

## Minimal plugin manifest

```yaml
name: zeaz-skills
version: "0.1.0"
description: Discover and load ZEAZ engineering skills on demand.
display_name: ZEAZ Skills
category: Developer Tools
include_skills:
  - skills/zeaz-skill-finder/
```

## Generation policy

Generated plugin files are build artifacts derived from:

- canonical `skills/`;
- `components.d/`;
- `plugins.d/`;
- shared defaults.

Do not hand-edit generated plugin output when a source manifest can express the change.

## Context-budget policy

Prefer a small finder/router skill that discovers a relevant skill on demand. Avoid preloading the whole catalog into every harness session merely for convenience.
