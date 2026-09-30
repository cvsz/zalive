# Component Catalog

Use one file per reusable component under `components.d/`.

This split avoids a single shared manifest becoming a merge hotspot as multiple teams add skills.

## File format

Create `components.d/<slug>.yml`:

```yaml
name: ZEAZ Example
repo: cvsz/example
description: One-line description.
skills:
  - path: skills/zeaz-example/
    catalog_dir: zeaz-example
```

## Required fields

- `name`: display name.
- `repo`: source repository in `owner/repo` form.
- `description`: concise component description.
- `skills`: list of skill source mappings.
- `skills[].path`: source directory containing one `SKILL.md`.
- `skills[].catalog_dir`: unique top-level directory under `skills/`.

## Policy

- Prefer one manifest per component.
- Prefer flat top-level skill directories for discoverability.
- Do not silently rename or remove catalog entries.
- Any exception to catalog rules must be documented with an owner and rationale.
- Catalog manifests describe reusable content; they do not grant authorization for production actions.
