#!/usr/bin/env python3
"""Interactive wrapper for the real-Apple activation attempt.

Prompts for the Apple ID and password via getpass so credentials are never
placed in argv, environment dumps readable by other local users, or shell
history. Requires the iPhone to be connected over USB and to be in the
state produced by a completed erase restore (ActivationState = Unactivated).

Prerequisites on this host:
  * /etc/hosts must NOT redirect albert.apple.com to 127.0.0.1
  * network access to Apple's activation endpoints

Usage:  ./scripts/try_activate.sh          (or)  ./venv/bin/python scripts/activate_real_apple.py
"""
import getpass
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
VENV_PY = ROOT / "venv" / "bin" / "python"
TARGET = ROOT / "scripts" / "activate_real_apple.py"


def pick_udid() -> str:
    out = subprocess.run(
        ["idevice_id", "-l"], capture_output=True, text=True, timeout=30
    ).stdout.split()
    if not out:
        sys.exit("No device found. Connect the iPhone over USB and check `idevice_id -l`.")
    if len(out) > 1:
        print("Multiple devices connected:")
        for i, u in enumerate(out, 1):
            print(f"  {i}. {u}")
        return out[int(input("Select UDID: ").strip()) - 1]
    return out[0]


def main() -> int:
    if not VENV_PY.exists():
        sys.exit(f"venv python not found at {VENV_PY}")
    if not TARGET.exists():
        sys.exit(f"activation script not found at {TARGET}")

    udid = pick_udid()
    print(f"Target UDID: {udid}")

    login = input("Apple ID (email): ").strip()
    if not login:
        sys.exit("Apple ID required.")
    password = getpass.getpass("Apple ID password (input hidden): ")

    env = {
        **os.environ,
        "TARGET_UDID": udid,
        "APPLE_LOGIN": login,
        "APPLE_PASSWORD": password,
    }
    try:
        result = subprocess.run(
            [str(VENV_PY), str(TARGET)], env=env, cwd=str(ROOT), check=False
        )
        return result.returncode
    finally:
        # Scrub the credentials from this process' environment copy.
        for key in ("APPLE_LOGIN", "APPLE_PASSWORD"):
            env.pop(key, None)
        password = ""
        del password


if __name__ == "__main__":
    sys.exit(main())
