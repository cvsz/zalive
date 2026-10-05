# Investigation Center

The zAlive Investigation Center is an evidence-backed workspace inspired by agent-oriented reverse-engineering UX, adapted for authorized device diagnostics and protocol research.

## What it does

- shows investigation tasks with explicit evidence state;
- lists the evidence files that support each task;
- presents structured findings with impact, confidence, evidence, and next action;
- exposes a machine-readable read-only tool catalog for future MCP/AI integration;
- keeps all device/account/DRM ownership bypass capabilities outside the tool surface.

## Evidence states

- `VERIFIED`: every declared evidence artifact for the task exists;
- `PARTIALLY_VERIFIED`: some declared evidence exists;
- `UNVERIFIED`: no declared evidence exists.

The UI does not claim that an agent is running unless there is a real worker/job system. Current task state is derived from repository evidence, not simulated progress.

## Routes

- `GET /investigation` — UI shell.
- `GET /api/investigation` — admin-gated JSON evidence state.

The JSON endpoint requires the same `X-Admin-Token` or bearer token used by other admin APIs.

## Safety

This workspace is for owned or explicitly authorized devices and research artifacts. It must not expose:

- Activation Lock or Apple ID bypass;
- credential/private-key extraction;
- FairPlay/DRM bypass;
- attestation bypass;
- destructive flashing;
- arbitrary device shell execution.

Future MCP tools should default to read-only evidence retrieval. Any execution worker must be isolated, explicitly authorized, bounded, and auditable.
