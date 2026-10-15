import os

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


def test_investigation_ui_and_admin_api(monkeypatch) -> None:
    monkeypatch.setenv("ALBERT_ADMIN_TOKEN", "test-investigation-token")
    import albert_server

    client = albert_server.app.test_client()

    page = client.get("/investigation")
    assert page.status_code == 200
    assert b"Investigation Center" in page.data

    unauthenticated = client.get("/api/investigation")
    assert unauthenticated.status_code == 401

    authenticated = client.get(
        "/api/investigation",
        headers={"X-Admin-Token": "test-investigation-token"},
    )
    assert authenticated.status_code == 200
    payload = authenticated.get_json()
    assert payload["mode"] == "evidence-backed-read-only"
    assert payload["progress"]["total"] >= 1
