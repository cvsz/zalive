"""Regression tests for activate_device.py device-identifier resolution.

The bug these guard against: ``get_device_info`` called ``_get_dev_id``,
a helper that was a *local* function inside ``activate_with_pymobiledevice3``
and therefore not in scope. It raised ``NameError``, which the broad
``except Exception`` turned into "no device connected or usbmuxd not
running" — a message that sent debugging toward USB instead of the code.

These tests pin the module-level helpers and the lookup behaviour so a
future refactor cannot reintroduce a private copy that callers reference
by the wrong name.
"""

import asyncio
import sys
import types
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import activate_device as ad  # noqa: E402


class _SerialDevice:
    """MuxDevice shape used by pymobiledevice3 >= 3.x."""

    def __init__(self, serial):
        self.serial = serial


class _LegacyDevice:
    """Pre-3.x shape: no .serial."""

    def __init__(self, udid):
        self.udid = udid


class _MiddleDevice:
    """Intermediate release exposing .identifier."""

    def __init__(self, identifier):
        self.identifier = identifier


class DeviceIdentifierTest(unittest.TestCase):
    def test_prefers_serial(self):
        d = _SerialDevice("00008020-AAAA")
        self.assertEqual(ad._device_identifier(d), "00008020-AAAA")

    def test_falls_back_to_udid(self):
        self.assertEqual(ad._device_identifier(_LegacyDevice("udid-x")), "udid-x")

    def test_falls_back_to_identifier(self):
        self.assertEqual(ad._device_identifier(_MiddleDevice("ident-y")), "ident-y")

    def test_falls_back_to_udid_underscore(self):
        class D:
            udid_ = "udid-under"

        self.assertEqual(ad._device_identifier(D()), "udid-under")

    def test_never_returns_none(self):
        class D:
            pass

        # str(device) is the last resort, so the helper always yields a string
        # rather than None reaching create_using_usbmux().
        self.assertIsInstance(ad._device_identifier(D()), str)


class DeviceMatchesUdidTest(unittest.TestCase):
    def test_no_udid_means_match(self):
        self.assertTrue(ad._device_matches_udid(_SerialDevice("a"), None))

    def test_serial_match(self):
        self.assertTrue(ad._device_matches_udid(_SerialDevice("u1"), "u1"))

    def test_serial_mismatch(self):
        self.assertFalse(ad._device_matches_udid(_SerialDevice("u1"), "u2"))

    def test_legacy_device_matched_by_udid(self):
        self.assertTrue(ad._device_matches_udid(_LegacyDevice("u1"), "u1"))

    def test_matches_udid_protocol_is_used(self):
        class WithProto(_SerialDevice):
            def matches_udid(self, u):
                return u == "via-proto"

        self.assertTrue(ad._device_matches_udid(WithProto("other"), "via-proto"))


class GetDeviceInfoScopeTest(unittest.TestCase):
    """The regression itself: `--info --udid` must not raise NameError."""

    def test_no_local_helper_definitions_leak(self):
        """get_device_info must use the module-level helper.

        A nested def in either call path is what caused the original bug.
        """
        import ast

        tree = ast.parse(Path(ad.__file__).read_text())
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            if node.name not in ("get_device_info", "activate_with_pymobiledevice3"):
                continue
            nested = {
                n.name
                for n in ast.walk(node)
                if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n is not node
            }
            self.assertNotIn(
                "_device_identifier", nested,
                f"{node.name} redefines _device_identifier locally; "
                "callers will reference the wrong binding",
            )

    def test_get_device_info_resolves_udid_end_to_end(self):
        async def run():
            device = _SerialDevice("00008020-AAAAAAAAAAAAAAAA")

            fake_module = types.ModuleType("pymobiledevice3.lockdown")

            class FakeLockdown:
                def __init__(self, serial):
                    self.serial = serial

                async def get_value(self, key=None, domain=None):
                    return {
                        "SerialNumber": "TESTSERIAL",
                        "ProductVersion": "18.7.10",
                        "ActivationState": "Unactivated",
                    }.get(key)

                @property
                def all_values(self):
                    return {"DeviceName": "TestPhone"}

            async def create_using_usbmux(serial=None, **kwargs):
                return FakeLockdown(serial)

            fake_module.create_using_usbmux = create_using_usbmux
            sys.modules["pymobiledevice3.lockdown"] = fake_module

            original_list_devices = ad.list_devices
            ad.list_devices = lambda: asyncio.sleep(0, result=[device])
            try:
                return await ad.get_device_info("00008020-AAAAAAAAAAAAAAAA")
            finally:
                ad.list_devices = original_list_devices

        info = asyncio.run(run())
        self.assertIsNotNone(info, "get_device_info returned None — scope bug is back")
        self.assertEqual(info["SerialNumber"], "TESTSERIAL")
        self.assertEqual(info["ProductVersion"], "18.7.10")
        self.assertEqual(info["DeviceName"], "TestPhone")


if __name__ == "__main__":
    unittest.main()