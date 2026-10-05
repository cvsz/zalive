from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent

EVIDENCE_FILES = {
    "protocol": "docs/re/ACTIVATION-PROTOCOL.md",
    "firmware": "docs/re/FIRMWARE-ANALYSIS-FINDINGS.md",
    "ipsw": "docs/re/IPSW-18.7.10-STRUCTURE.md",
    "work_report": "docs/re/WORK-REPORT.md",
    "activation_trace": "docs/re/activation_trace.json",
    "handshake_decode": "docs/re/handshake_decode.json",
    "handshake_framing": "docs/re/handshake_framing.json",
}

TASKS = [
    {
        "id": "artifact-triage",
        "agent": "Artifact Triage",
        "title": "Inventory authorized research artifacts",
        "evidence": ["work_report", "ipsw"],
        "capability": "metadata-only",
    },
    {
        "id": "firmware-structure",
        "agent": "Firmware Structure Analyst",
        "title": "Map IPSW and firmware structure",
        "evidence": ["firmware", "ipsw"],
        "capability": "static-analysis",
    },
    {
        "id": "protocol-trace",
        "agent": "Protocol Trace Analyst",
        "title": "Correlate captured activation/handshake evidence",
        "evidence": ["activation_trace", "handshake_decode", "handshake_framing"],
        "capability": "trace-analysis",
    },
    {
        "id": "trust-boundary",
        "agent": "Trust Boundary Analyst",
        "title": "Document trust anchors and non-bypassable boundaries",
        "evidence": ["protocol", "work_report"],
        "capability": "evidence-synthesis",
    },
    {
        "id": "report",
        "agent": "Evidence Reporter",
        "title": "Produce evidence-backed findings and next actions",
        "evidence": ["protocol", "firmware", "work_report"],
        "capability": "reporting",
    },
]

FINDINGS = [
    {
        "id": "trust-anchor",
        "title": "Activation trust remains anchored to Apple-controlled signing",
        "impact": "A local research server can emulate protocol handling but cannot substitute for Apple-owned trust material.",
        "confidence": "HIGH",
        "evidence": ["docs/re/ACTIVATION-PROTOCOL.md", "docs/re/WORK-REPORT.md"],
        "action": "Use local endpoints for protocol research, compatibility testing, and diagnostics only.",
    },
    {
        "id": "evidence-separation",
        "title": "Static observations must remain separate from runtime proof",
        "impact": "Protocol strings, plist fields, firmware symbols, and decoded structures do not by themselves prove runtime behavior.",
        "confidence": "HIGH",
        "evidence": ["docs/re/FIRMWARE-ANALYSIS-FINDINGS.md", "docs/re/WORK-REPORT.md"],
        "action": "Promote a finding to confirmed only when trace/runtime evidence supports it.",
    },
    {
        "id": "owned-device-boundary",
        "title": "Research scope is limited to owned or explicitly authorized devices",
        "impact": "Ownership, account, DRM, activation-lock, and attestation controls remain outside the allowed automation surface.",
        "confidence": "HIGH",
        "evidence": ["SECURITY.md", "NOTICE", "README.md"],
        "action": "Keep bypass-oriented capabilities excluded from agents, APIs, and future MCP tools.",
    },
]


def _evidence_state(keys: list[str]) -> tuple[str, list[dict[str, Any]]]:
    rows: list[dict[str, Any]] = []
    present = 0
    for key in keys:
        rel = EVIDENCE_FILES[key]
        path = ROOT / rel
        exists = path.is_file()
        present += int(exists)
        rows.append({"key": key, "path": rel, "present": exists})
    if present == len(keys):
        state = "VERIFIED"
    elif present:
        state = "PARTIALLY_VERIFIED"
    else:
        state = "UNVERIFIED"
    return state, rows


def build_investigation_state() -> dict[str, Any]:
    tasks = []
    for task in TASKS:
        state, evidence = _evidence_state(task["evidence"])
        tasks.append({**task, "state": state, "evidence": evidence})

    verified = sum(task["state"] == "VERIFIED" for task in tasks)
    total = len(tasks)
    progress = round((verified / total) * 100) if total else 0

    catalog_path = ROOT / "catalog/investigation-tools.json"
    catalog = {}
    if catalog_path.is_file():
        catalog = json.loads(catalog_path.read_text(encoding="utf-8"))

    return {
        "schema_version": "1.0",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "mode": "evidence-backed-read-only",
        "progress": {"verified": verified, "total": total, "percent": progress},
        "tasks": tasks,
        "findings": FINDINGS,
        "tool_catalog": catalog,
        "safety": {
            "authorized_research_only": True,
            "activation_lock_bypass": False,
            "credential_extraction": False,
            "drm_bypass": False,
            "destructive_flashing": False,
            "arbitrary_command_execution": False,
        },
    }
