"""Lifecycle tests use temporary directories and simulated launchctl responses."""
import importlib.util
import json
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
        for name in ('guard.py', 'watchdog'):
            (root / name).write_text('fixture')
        (root / 'state.json').write_text(json.dumps({'version': 1, 'modes': {}, 'jobs': {}}))
        data = {'Label': label, 'ProgramArguments': ['/test/python3', '-I', str(root / 'guard.py')]}
        plist.write_bytes(plistlib.dumps(data))
        return root, plist, label, '/test/python3'

    def test_dynamic_runtime_and_branding(self):
        data = manage.make_plist('/chosen/python3')
        self.assertEqual(data['Label'], 'local.watchdog.guard')
        self.assertEqual(data['ProgramArguments'][0], '/chosen/python3')
        self.assertTrue(data['KeepAlive'])

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
        with patch.object(manage, 'service_loaded', side_effect=[True, False]), patch.object(manage, 'run', side_effect=command) as commands:
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


if __name__ == '__main__':
    unittest.main()
