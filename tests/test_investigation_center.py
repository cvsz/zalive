from investigation_center import build_investigation_state


def test_investigation_state_is_evidence_backed() -> None:
    state = build_investigation_state()
    assert state["schema_version"] == "1.0"
    assert state["mode"] == "evidence-backed-read-only"
    assert state["tasks"]
    assert all(task["state"] in {"VERIFIED", "PARTIALLY_VERIFIED", "UNVERIFIED"} for task in state["tasks"])


def test_investigation_excludes_bypass_capabilities() -> None:
    state = build_investigation_state()
    safety = state["safety"]
    assert safety["authorized_research_only"] is True
    assert safety["activation_lock_bypass"] is False
    assert safety["credential_extraction"] is False
    assert safety["drm_bypass"] is False
    assert safety["destructive_flashing"] is False
    assert safety["arbitrary_command_execution"] is False
