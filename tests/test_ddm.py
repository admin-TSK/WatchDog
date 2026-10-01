"""DDM shield tests. Temporary files only; no live pfctl."""
import importlib.util
import os
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def load(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / 'src' / f'{name}.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


ddm = load('ddm')
network = load('network')
shields = load('shields')


class DdmTests(unittest.TestCase):
    def policy(self):
        return network.load_policy(ROOT / 'src' / 'network_policy.json')

    def test_catalog_and_mode_selection(self):
        self.assertEqual(ddm.action_for('com.apple.configuration.app.managed'), 'restrict')
        self.assertEqual(ddm.action_for('com.apple.configuration.softwareupdate.settings'), 'remove')
        self.assertEqual(ddm.action_for('com.apple.configuration.passcode.settings'), 'not_removed')
        policy = self.policy()
        on_ids = {group['id'] for group in network.groups_for_mode(policy, 'on')}
        self.assertNotIn('apple-software-update', on_ids)
        self.assertNotIn('apple-app-store', on_ids)
        groups = ddm.extra_groups(policy, {'ddm-installs': True}, ['pkg.example.com'])
        ids = [group['id'] for group in groups]
        self.assertEqual(ids, ['jamf-management', 'apple-app-store', 'ddm-manifests'])
        self.assertNotIn('jamf-sentry', ids)
        self.assertEqual(groups[-1]['hosts'], ['pkg.example.com'])
        self.assertTrue(groups[-1]['hosts'])

    def test_manifest_url_drops_path_and_credentials(self):
        hosts, partial = ddm.hosts_from_blob('https://user:secret@pkg.example.com:443/path/app.pkg?token=1')
        self.assertEqual(hosts, ['pkg.example.com'])
        self.assertEqual(partial, [])
        self.assertNotIn('secret', hosts[0])
        wild_hosts, wild_partial = ddm.hosts_from_blob('https://*.cdn.example.com/pkg')
        self.assertEqual(wild_hosts, [])
        self.assertEqual(wild_partial, ['wildcard'])
        self.assertEqual(ddm.extra_groups(self.policy(), {'ddm-assets': True}, []), [])

    def test_channel_off_is_ignored_while_installs_are_on(self):
        current = shields.from_config()
        current['ddm-installs'] = True
        current['ddm-channel'] = True
        result = shields.apply(current, {'id': 'ddm-channel', 'enabled': False})
        self.assertTrue(result['ddm-channel'])
        self.assertTrue(result['ddm-installs'])

    def test_snapshot_is_write_once_and_marker_does_not_replace_it(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'SoftwareUpdateDDMStatePersistence.plist'
            path.write_bytes(b'<plist>original-enforcement</plist>')
            record = {}
            self.assertEqual(ddm.capture_snapshot(record, path), 'snapshotted')
            original = record['softwareupdate']['content_b64']
            path.write_bytes(b'<plist>rewritten-by-system</plist>')
            self.assertEqual(ddm.capture_snapshot(record, path), 'snapshotted')
            self.assertEqual(record['softwareupdate']['content_b64'], original)
            status, rewrote = ddm.hold_software_update(record, path)
            self.assertEqual(status, 'removed')
            self.assertTrue(rewrote)
            self.assertEqual(path.read_bytes(), ddm.MARKER)
            self.assertEqual(record['softwareupdate']['content_b64'], original)
            status, rewrote = ddm.hold_software_update(record, path)
            self.assertEqual(status, 'removed')
            self.assertFalse(rewrote)
            self.assertIsNone(ddm.revert_software_update(record, path))
            self.assertEqual(path.read_bytes(), b'<plist>original-enforcement</plist>')

    def test_absent_symlink_and_oversize_do_not_remove(self):
        with tempfile.TemporaryDirectory() as temp:
            missing = Path(temp) / 'missing.plist'
            record = {}
            self.assertEqual(ddm.capture_snapshot(record, missing), 'snapshotted')
            self.assertTrue(record['softwareupdate']['absent'])
            status, rewrote = ddm.hold_software_update(record, missing)
            self.assertEqual((status, rewrote), ('restricted', False))
            self.assertFalse(missing.exists())

            target = Path(temp) / 'real.plist'
            target.write_bytes(b'real')
            link = Path(temp) / 'link.plist'
            os.symlink(target, link)
            linked = {}
            self.assertEqual(ddm.capture_snapshot(linked, link), 'not_removed')
            self.assertNotIn('softwareupdate', linked)
            self.assertEqual(target.read_bytes(), b'real')

            huge = Path(temp) / 'huge.plist'
            huge.write_bytes(b'x' * (ddm.MAX_SNAPSHOT + 1))
            oversized = {}
            self.assertEqual(ddm.capture_snapshot(oversized, huge), 'not_removed')
            self.assertNotIn('softwareupdate', oversized)

    def test_revert_failure_is_reported(self):
        with tempfile.TemporaryDirectory() as temp:
            record = {'softwareupdate': {
                'absent': False,
                'content_b64': 'b3JpZ2luYWw=',
                'mode': 0o644,
                'flags': 0,
            }}
            error = ddm.revert_software_update(record, temp)
            self.assertTrue(error)
            self.assertIn('content_b64', record['softwareupdate'])

    def test_public_status_omits_snapshot_bytes(self):
        record = {'softwareupdate': {'content_b64': 'c2VjcmV0', 'absent': False},
                  'softwareupdate_status': 'removed',
                  'types': ['com.apple.configuration.app.managed']}
        status = ddm.public_status({'ddm-update': True}, record, 'off', True)
        self.assertNotIn('c2VjcmV0', str(status))
        self.assertEqual(status['tiles']['ddm-update'], 'removed')
        self.assertEqual(status['tiles']['ddm-channel'], 'forced')
        self.assertEqual(status['types'], ['com.apple.configuration.app.managed'])


if __name__ == '__main__':
    unittest.main()
