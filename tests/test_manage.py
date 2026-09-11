"""Lifecycle tests use temporary directories and simulated launchctl responses."""
import importlib.util
import json
import os
from pathlib import Path
import plistlib
import subprocess
import tempfile
import unittest
from unittest.mock import patch

REPO = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('manage', REPO / 'src/manage.py')
manage = importlib.util.module_from_spec(spec)
spec.loader.exec_module(manage)


class LifecycleTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='watchdog-lifecycle-')
        self.root = Path(self.tmp.name)
        self.patches = [patch.object(manage, name, value) for name, value in {
            'ROOT': self.root / 'WatchDog',
            'LEGACY_ROOT': self.root / 'Legacy',
            'LAUNCHDAEMONS': self.root / 'LaunchDaemons',
            'PLIST': self.root / 'LaunchDaemons/local.watchdog.guard.plist',
            'AUDIT_DIR': self.root / 'logs',
            'NEWSYSLOG': self.root / 'newsyslog.conf',
            'EVENTS_JSON': self.root / 'events.json',
            'APPLICATION': self.root / 'WatchDog.app',
        }.items()]
        for p in self.patches: p.start()
        manage.LAUNCHDAEMONS.mkdir()
        manage.AUDIT_DIR.mkdir()

    def tearDown(self):
        for p in reversed(self.patches): p.stop()
        self.tmp.cleanup()

    def fixture(self, legacy=False):
        root = manage.LEGACY_ROOT if legacy else manage.ROOT
        label = 'local.example.jamf-test-blocker' if legacy else manage.LABEL
        plist = manage.LAUNCHDAEMONS / f'{label}.plist'
        root.mkdir()
        for name in ('guard.py', 'processes.py', 'watchdog'):
            (root / name).write_text('fixture')
        (root / 'state.json').write_text(json.dumps({'version': 1, 'modes': {}, 'jobs': {}}))
        data = {'Label': label, 'ProgramArguments': ['/test/python3', '-I', str(root / 'guard.py')]}
        plist.write_bytes(plistlib.dumps(data))
        return root, plist, label, '/test/python3'

    def test_dynamic_runtime_and_branding(self):
        data = manage.make_plist('/chosen/python3')
        self.assertEqual(data['Label'], 'local.watchdog.guard')
        self.assertEqual(data['ProgramArguments'], [str(manage.ROOT / 'run-guard')])
        self.assertTrue(data['KeepAlive'])
        self.assertEqual(manage.python_fallbacks('/chosen/python3')[0], '/chosen/python3')
        self.assertIn('/usr/bin/python3', manage.python_fallbacks('/chosen/python3'))
        self.assertTrue(manage.interpreter_volatile('/Library/Frameworks/Python.framework/Versions/3.14/bin/python3'))
        self.assertFalse(manage.interpreter_volatile('/usr/bin/python3'))
        runner = self.root / 'run-guard'
        manage.write_runner(runner, 'guard.py', manage.python_fallbacks('/chosen/python3'))
        text = runner.read_text()
        self.assertIn('/chosen/python3', text)
        self.assertIn('/usr/bin/python3', text)
        self.assertIn('sys.version_info < (3, 10)', text)

    def test_legacy_detection_and_duplicate_install_refusal(self):
        expected = self.fixture(legacy=True)
        self.assertEqual(manage.installed(), expected)
        with patch.object(manage, 'run') as commands:
            with self.assertRaisesRegex(RuntimeError, 'already installed'):
                manage.install()
            commands.assert_not_called()
        self.assertTrue(expected[0].exists())

    def test_uninstall_restores_before_removal(self):
        root, plist, label, python = self.fixture()
        def command(*args, **kwargs):
            if '--restore' in args:
                self.assertTrue((root / 'state.json').exists())
                self.assertTrue(plist.exists())
            return subprocess.CompletedProcess(args, 0, '', '')
        with patch.object(manage, 'service_loaded', side_effect=[True, False, False]), patch.object(manage, 'run', side_effect=command) as commands:
            manage.uninstall()
        self.assertFalse(root.exists())
        self.assertFalse(plist.exists())
        self.assertEqual(len(list(manage.AUDIT_DIR.glob('*.json'))), 1)
        self.assertEqual(commands.call_args_list[0].args[:2], ('/bin/launchctl', 'bootout'))
        self.assertIn('--restore', commands.call_args_list[1].args)

    def test_failed_restore_retains_recovery_files(self):
        root, plist, label, python = self.fixture(legacy=True)
        with patch.object(manage, 'service_loaded', return_value=False), patch.object(manage, 'run', side_effect=subprocess.CalledProcessError(1, 'restore')):
            with self.assertRaises(subprocess.CalledProcessError):
                manage.uninstall()
        self.assertTrue((root / 'state.json').exists())
        self.assertTrue(plist.exists())

    def test_status_reports_companion_and_tracked_paths(self):
        root, plist, label, python = self.fixture()
        (root / 'state.json').write_text(json.dumps({
            'version': 2, 'modes': {str(root / 'component'): 0o755}, 'jobs': {'system/com.jamf.management.daemon': {}}, 'flags': {}
        }))
        (root / 'component').write_text('x')
        (root / 'component').chmod(0o644)
        (root / 'installation.json').write_text(json.dumps({
            'version': '0.3.0', 'sticky_block': False, 'match_signature': False, 'block_connect': False
        }))
        launchctl = subprocess.CompletedProcess([], 0, 'state = running\n pid = 99\n', '')
        with patch.object(manage, 'run', return_value=launchctl), \
             patch('os.lstat', wraps=os.lstat), \
             patch('sys.stdout', new_callable=__import__('io').StringIO) as stdout:
            manage.status()
        text = stdout.getvalue()
        self.assertIn('WatchDog: running', text)
        self.assertIn('Event reader:', text)
        self.assertIn('Menu bar app:', text)
        self.assertIn('Tracked executables: 1', text)
        self.assertIn('Jamf Connect blocking: False', text)
        self.assertIn('MDM enrollment stays intact. Network On denies Jamf and Apple HTTPS check-in; Yeet also denies APNs.', text)

    def test_status_reports_live_shields(self):
        root, plist, label, python = self.fixture()
        (root / 'installation.json').write_text(json.dumps({
            'version': '0.3.1', 'sticky_block': False, 'match_signature': False, 'block_connect': False
        }))
        (root / 'shields.json').write_text(json.dumps({
            'permissions': True, 'jobs': False, 'monitor': True, 'sticky': False, 'signatures': False, 'connect': False
        }))
        launchctl = subprocess.CompletedProcess([], 0, 'state = running\n pid = 99\n', '')
        with patch.object(manage, 'run', return_value=launchctl), \
             patch('sys.stdout', new_callable=__import__('io').StringIO) as stdout:
            manage.status()
        self.assertIn('jobs=off', stdout.getvalue())
        self.assertIn('permissions=on', stdout.getvalue())


if __name__ == '__main__':
    unittest.main()
