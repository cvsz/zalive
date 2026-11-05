import os
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def _help_with_host(host: str | None) -> str:
    env = os.environ.copy()
    env.pop("ALBERT_HOST", None)
    if host is not None:
        env["ALBERT_HOST"] = host
    result = subprocess.run(
        [sys.executable, str(ROOT / "albert_server.py"), "--help"],
        cwd=ROOT,
        env=env,
        check=True,
        capture_output=True,
        text=True,
        timeout=15,
    )
    return result.stdout


def test_cli_defaults_to_loopback_bind():
    assert "default: 127.0.0.1" in _help_with_host(None)


def test_cli_allows_explicit_host_bind_override():
    assert "default: 0.0.0.0" in _help_with_host("0.0.0.0")


def test_gunicorn_defaults_to_loopback_bind(monkeypatch):
    monkeypatch.delenv("ALBERT_HOST", raising=False)
    monkeypatch.setenv("ALBERT_HTTP_PORT", "18090")
    import runpy

    config = runpy.run_path(str(ROOT / "gunicorn_conf.py"))
    assert config["bind"] == "127.0.0.1:18090"
