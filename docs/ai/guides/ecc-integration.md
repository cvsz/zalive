# ECC Integration

This template includes a root `ecc-install.json` as an **OSS ECC CLI install configuration** using install-config schema version 1.

## Why the OSS CLI config is minimal

The template intentionally does not select a `target`, `profile`, or module set. Those choices are project- and harness-specific and should be made after a repository is created from this template.

The config therefore establishes a supported ECC CLI configuration surface without forcing Claude, Codex, OpenCode, Cursor, hooks, language packs, or other runtime choices onto every generated repository.

## OSS CLI upstream contract

Verified against the ECC upstream installer contract at commit:

`90dfd9505dc860714cf3cc8216ad7bbb96d93365`

Relevant upstream files:

- `scripts/lib/install/config.js` — default project config filename is `ecc-install.json`
- `schemas/ecc-install-config.schema.json` — schema version 1; only `version` is required
- `manifests/install-profiles.json` — profiles such as minimal, core, developer, security, research, and full

The schema URL in `ecc-install.json` is commit-pinned for reproducibility. This user-authored config does not contain, replace, authenticate, or prove any ECC GitHub App-generated identity, install-state, provenance, or analysis manifest.

## ECC GitHub App separation

ECC GitHub App analysis may generate repository-specific identity, harness, install-state, provenance, or analysis artifacts. Those hosted artifacts are separate evidence surfaces. Presence of `ecc-install.json` must never be treated as proof that an App analysis ran or that App-generated manifests are valid/current.

## Project setup

After creating a repository from this template, review ECC's current setup documentation and select the smallest appropriate target/profile. Do not copy a full profile merely to satisfy an audit metric.

A current guided setup may be started with:

```bash
npx ecc-universal@2.2.1 install --guided
```

Review the planned destinations and mutations before applying them.

## Drift policy

- Do not silently change the pinned schema reference.
- Re-verify upstream schema and installer behavior before updating the pin.
- Keep OSS ECC runtime configuration, ECC GitHub App-generated artifacts, and this repository's readiness claims as separate evidence surfaces.
- Installing ECC components does not make a generated project production ready.
