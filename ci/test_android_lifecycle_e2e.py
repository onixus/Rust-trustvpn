"""Synthetic harness ownership regressions; no adb, Gradle, device or VPN writes."""
from contextlib import nullcontext, redirect_stderr, redirect_stdout
import io
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

import android_lifecycle_e2e as harness
import android as pipeline

PACKAGE = 'org.rtrusttunnel.android.run_synthetic.lifecycle_test'
TEST_PACKAGE = PACKAGE + '.test'


def connectivity_dump(transport='WIFI', nested='', later=''):
    return ('Active default network: 100\n\nCurrent Networks:\n'
            '  NetworkAgentInfo{network{100} ni{CONNECTED} nc{[ Transports: '
            + transport + ' Capabilities: INTERNET ]}}\n' + nested
            + '\nStatus for known UIDs:\n\nNetwork Requests:\n' + later)


class ConnectivityParserTests(unittest.TestCase):
    def test_passive_vpn_listen_request_is_not_active(self):
        self.assertFalse(harness.has_current_vpn(connectivity_dump(later=
            '  NetworkRequest [ LISTEN id=9, [ Transports: VPN ] ]\n')))

    def test_historical_release_and_agent_logs_are_not_current(self):
        self.assertFalse(harness.has_current_vpn(connectivity_dump(later=
            'mNetworkRequestInfoLogs (most recent first):\n'
            '  RELEASE NetworkRequest [ LISTEN id=9, [ Transports: VPN ] ]\n'
            '  NetworkAgentInfo{nc{[ Transports: VPN ]}}\n')))

    def test_nested_requests_in_current_networks_are_not_agents(self):
        self.assertFalse(harness.has_current_vpn(connectivity_dump(nested=
            '    Requests: REQUEST:1 LISTEN:1 BACKGROUND_REQUEST:0 total:2\n'
            '      NetworkRequest [ LISTEN id=9, [ Transports: VPN ] ]\n'
            '    Inactivity Timers:\n')))

    def test_vpn_and_combined_transports_remain_blocked(self):
        for value in ('VPN', 'WIFI|VPN', 'CELLULAR|VPN', 'VPN|WIFI'):
            with self.subTest(value=value):
                self.assertTrue(harness.has_current_vpn(connectivity_dump(value)))

    def test_empty_current_network_section_is_observed_idle(self):
        self.assertFalse(harness.has_current_vpn('Current Networks:\n\nNetwork Requests:\n'))

    def test_unknown_truncated_or_malformed_output_fails_closed(self):
        samples = (
            '', 'Transports: WIFI', 'Permission denied',
            'Current Networks:\n  NetworkAgentInfo{nc{[ Transports: WIFI ]}}',
            'Current Networks:\nUnknown section:\n',
            'Current Networks:\n  UnexpectedRow\nNetwork Requests:\n',
            connectivity_dump('FUTURE_TRANSPORT'),
            connectivity_dump().replace('nc{[ Transports:', 'unknown{[ Transports:'),
            connectivity_dump().replace('INTERNET ]}}', 'INTERNET'),
            connectivity_dump() + 'Current Networks:\n',
        )
        for value in samples:
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    harness.has_current_vpn(value)

    def test_dump_size_is_bounded(self):
        with self.assertRaises(ValueError):
            harness.has_current_vpn('x' * (4 * 1024 * 1024 + 1))


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
            output = connectivity_dump('VPN' if self.active else 'WIFI')
        elif cmd[:4] == ['shell', 'pm', 'list', 'packages']:
            output = '\n'.join('package:' + name for name in self.packages if cmd[-1] in name)
        elif cmd[0] == 'install':
            self.install_count += 1
            name = PACKAGE if self.install_count == 1 else TEST_PACKAGE
            self.packages.add(name)
            if self.failure == 'install-' + str(self.install_count):
                raise subprocess.CalledProcessError(1, command)
            if self.failure == 'install-timeout-' + str(self.install_count):
                raise subprocess.TimeoutExpired(command, 180)
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

    def test_timed_out_first_install_does_not_grant_cleanup_ownership(self):
        device = Device(failure='install-timeout-1')
        with self.assertRaises(subprocess.TimeoutExpired):
            self.invoke(device)
        self.assertEqual(device.packages, {PACKAGE})
        self.assertEqual(len(device.mutations()), 1)

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


class PipelineBranchTests(unittest.TestCase):
    def invoke(self, lifecycle_only, fail_network=False):
        args = ['test', '--serial', 'emulator-5554', '--gradle', 'synthetic-gradle']
        if lifecycle_only:
            args.append('--lifecycle-only')
        def execute(command, **kwargs):
            if fail_network and 'ci/android_network_e2e.py' in command:
                raise RuntimeError('Synthetic required network gate failure')
        fixture = Mock()
        fixture.poll.return_value = None
        fixture.wait.return_value = 0
        with patch.object(sys, 'argv', args), \
             patch.object(pipeline.Path, 'is_dir', return_value=True), \
             patch.object(pipeline.Path, 'mkdir'), \
             patch.object(pipeline.Path, 'exists', return_value=True), \
             patch.object(pipeline.signal, 'signal'), \
             patch.object(pipeline.subprocess, 'run', return_value=SimpleNamespace(returncode=0)), \
             patch.object(pipeline.subprocess, 'Popen', return_value=fixture) as popen, \
             patch.object(pipeline, 'run', side_effect=execute) as run, \
             patch.object(pipeline.shutil, 'copy2') as copy, \
             patch.dict(sys.modules, {'hysteria_interop': SimpleNamespace(binary=lambda: None),
                                      'amneziawg_server': SimpleNamespace(binary=lambda: None)}), \
             redirect_stdout(io.StringIO()):
            try:
                pipeline.main()
            finally:
                self.last_commands = [call.args[0] for call in run.call_args_list]
            return self.last_commands, popen.call_count, copy.call_count

    def test_explicit_lifecycle_builds_then_runs_only_isolated_acceptance(self):
        commands, fixtures, copies = self.invoke(True)
        self.assertEqual(fixtures, 0)
        self.assertEqual(copies, 0)
        self.assertEqual(sum('ci/android_lifecycle_e2e.py' in cmd for cmd in commands), 1)
        self.assertFalse(any(any(name in cmd for name in ('ci/android_smoke.py',
            'ci/android_network_e2e.py', 'ci/android_always_on_e2e.py',
            'ci/android_process_death_e2e.py', 'ci/android_upgrade_e2e.py')) for cmd in commands))
        build = next(cmd for cmd in commands if cmd[0] == 'synthetic-gradle')
        self.assertTrue(all(task in build for task in ('assembleDebug', 'assembleRelease',
                                                     'assembleDebugAndroidTest', 'lintDebug')))
        native = next(cmd for cmd in commands if 'rtrust-android-lifecycle-target:/work/target' in cmd)
        self.assertIn('cargo test --locked -p rtrust-android -p rtrust-engine', native[-1])
        self.assertLess(commands.index(build), next(i for i, cmd in enumerate(commands)
                                                   if 'ci/android_lifecycle_e2e.py' in cmd))
        self.assertFalse(any('rtrust-android-target:/work/target' in cmd for cmd in commands))

    def test_default_network_failure_is_not_replaced_by_lifecycle_pass(self):
        with self.assertRaises(RuntimeError):
            self.invoke(False, fail_network=True)
        self.assertFalse(any('ci/android_lifecycle_e2e.py' in cmd for cmd in self.last_commands))

    def test_default_keeps_complete_network_and_product_pipeline(self):
        commands, fixtures, copies = self.invoke(False)
        self.assertEqual(fixtures, 4)
        self.assertEqual(copies, 2)
        self.assertEqual(sum('ci/android_network_e2e.py' in cmd for cmd in commands), 4)
        for name in ('ci/android_smoke.py', 'ci/android_always_on_e2e.py',
                     'ci/android_process_death_e2e.py', 'ci/android_upgrade_e2e.py',
                     'ci/android_lifecycle_e2e.py'):
            self.assertEqual(sum(name in cmd for cmd in commands), 1)
        self.assertTrue(any('rtrust-android-target:/work/target' in cmd for cmd in commands))
        self.assertFalse(any('rtrust-android-lifecycle-target:/work/target' in cmd for cmd in commands))


if __name__ == '__main__':
    unittest.main()
