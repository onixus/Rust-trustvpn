"""Synthetic harness ownership regressions; no adb, Gradle, device or VPN writes."""
from contextlib import nullcontext, redirect_stderr, redirect_stdout
import io
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import android_lifecycle_e2e as harness

PACKAGE = 'org.rtrusttunnel.android.run_synthetic.lifecycle_test'
TEST_PACKAGE = PACKAGE + '.test'


class Device:
    def __init__(self, after_build=None, failure=None):
        self.packages = set()
        self.calls = []
        self.active = False
        self.after_build = after_build
        self.failure = failure
        self.install_count = 0

    def run(self, command, **kwargs):
        self.calls.append(command)
        if command[0] == 'synthetic-gradle':
            if self.after_build:
                self.after_build(self)
            return SimpleNamespace(stdout='')
        cmd = command[3:]
        output = ''
        if cmd[:3] == ['shell', 'getprop', 'ro.kernel.qemu']:
            output = '1'
        elif cmd[:4] == ['shell', 'settings', 'get', 'secure']:
            output = 'null'
        elif cmd[:3] == ['shell', 'dumpsys', 'connectivity']:
            output = 'Transports: VPN' if self.active else 'Transports: WIFI'
        elif cmd[:4] == ['shell', 'pm', 'list', 'packages']:
            output = '\n'.join('package:' + name for name in self.packages if cmd[-1] in name)
        elif cmd[0] == 'install':
            self.install_count += 1
            name = PACKAGE if self.install_count == 1 else TEST_PACKAGE
            self.packages.add(name)
            if self.failure == 'install-' + str(self.install_count):
                raise subprocess.CalledProcessError(1, command)
            output = 'Success'
        elif cmd[:3] == ['shell', 'appops', 'set'] and self.failure == 'late-vpn':
            self.active = True
        elif cmd[0] == 'uninstall':
            self.packages.remove(cmd[-1])
            output = 'Success'
        elif cmd[:3] == ['shell', 'am', 'instrument']:
            if self.failure == 'instrument':
                raise subprocess.TimeoutExpired(command, 180)
            output = 'PASS: immediate STOP/START\nINSTRUMENTATION_CODE: -1'
        return SimpleNamespace(stdout=output)

    def mutations(self):
        return [cmd[3:] for cmd in self.calls if cmd[0] != 'synthetic-gradle'
                and (cmd[3:4] in (['install'], ['uninstall'])
                     or cmd[3:6] == ['shell', 'am', 'force-stop'])]


class HarnessTests(unittest.TestCase):
    def invoke(self, device):
        with patch.object(sys, 'argv', ['test', '--serial', 'emulator-5554', '--gradle', 'synthetic-gradle']), \
             patch.object(harness, 'application_id', return_value=PACKAGE), \
             patch.object(harness, 'emulator_lock', return_value=nullcontext()), \
             patch.object(harness.subprocess, 'run', side_effect=device.run), \
             redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            harness.main()

    def test_late_foreign_package_after_build_is_preserved(self):
        device = Device(after_build=lambda device: device.packages.add(PACKAGE))
        with self.assertRaises(SystemExit):
            self.invoke(device)
        self.assertEqual(device.packages, {PACKAGE})
        self.assertEqual(device.mutations(), [])

    def test_late_vpn_after_build_prevents_installation(self):
        device = Device(after_build=lambda device: setattr(device, 'active', True))
        with self.assertRaises(SystemExit):
            self.invoke(device)
        self.assertTrue(device.active)
        self.assertEqual(device.mutations(), [])

    def test_failed_first_install_does_not_clean_unacknowledged_package(self):
        device = Device(failure='install-1')
        with self.assertRaises(subprocess.CalledProcessError):
            self.invoke(device)
        self.assertEqual(device.packages, {PACKAGE})
        self.assertEqual(len(device.mutations()), 1)  # failed install only

    def test_failed_second_install_cleans_only_confirmed_first(self):
        device = Device(failure='install-2')
        with self.assertRaises(subprocess.CalledProcessError):
            self.invoke(device)
        self.assertEqual(device.packages, {TEST_PACKAGE})
        stops = [cmd[-1] for cmd in device.mutations() if cmd[:3] == ['shell', 'am', 'force-stop']]
        self.assertEqual(stops, [PACKAGE])

    def test_instrument_timeout_cleans_both_confirmed_owned_packages(self):
        device = Device(failure='instrument')
        with self.assertRaises(subprocess.TimeoutExpired):
            self.invoke(device)
        self.assertEqual(device.packages, set())
        uninstalls = [cmd[-1] for cmd in device.mutations() if cmd[0] == 'uninstall']
        self.assertEqual(uninstalls, [TEST_PACKAGE, PACKAGE])

    def test_late_vpn_before_instrumentation_is_preserved(self):
        device = Device(failure='late-vpn')
        with self.assertRaises(SystemExit):
            self.invoke(device)
        self.assertTrue(device.active)
        self.assertEqual(device.packages, set())
        self.assertFalse(any(cmd[3:6] == ['shell', 'am', 'instrument'] for cmd in device.calls))

    def test_success_cleans_owned_packages(self):
        device = Device()
        self.invoke(device)
        self.assertEqual(device.packages, set())

    def test_invocations_have_distinct_application_ids(self):
        names = {harness.application_id() for _ in range(100)}
        self.assertEqual(len(names), 100)
        self.assertTrue(all(name.endswith('.lifecycle_test') for name in names))

    def test_emulator_lock_is_bounded_preserved_and_reusable(self):
        # Actual advisory-lock contention on synthetic temporary files only.
        with tempfile.TemporaryDirectory(prefix='rtrust-lock-test-') as directory:
            with patch.object(harness, 'Path', return_value=Path(directory)):
                with harness.emulator_lock('emulator-5554', 0):
                    with self.assertRaises(TimeoutError):
                        with harness.emulator_lock('emulator-5554', 0):
                            self.fail('busy lock unexpectedly acquired')
                    self.assertEqual(len(list(Path(directory).rglob('*.lock'))), 1)
                with harness.emulator_lock('emulator-5554', 0):
                    pass


if __name__ == '__main__':
    unittest.main()
