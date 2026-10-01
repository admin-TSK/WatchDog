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
        self.assertEqual([group['id'] for group in groups], ['ddm-manifests'])
        self.assertEqual(groups[0]['hosts'], ['pkg.example.com'])
        every = {
            'ddm-channel': True, 'ddm-push': True, 'ddm-update': True,
            'ddm-installs': True, 'ddm-assets': True,
        }
        mixed = ['apps.apple.com', 'swcdn.apple.com', 'jss.example.com', 'pkg.example.com']
        selected = ddm.extra_groups(policy, every, mixed, ['jss.example.com'])
        ids = {group['id'] for group in selected}
        self.assertEqual(ids, {'ddm-manifests'})
        self.assertNotIn('apns', ids)
        self.assertNotIn('jamf-management', ids)
        self.assertEqual(selected[0]['hosts'], ['pkg.example.com'])
        self.assertEqual(ddm.extra_groups(policy, every, ['apps.apple.com', 'jss.example.com'], ['jss.example.com']), [])

    def test_manifest_url_drops_path_and_credentials(self):
        hosts, partial = ddm.hosts_from_blob('https://user:secret@pkg.example.com:443/path/app.pkg?token=1')
        self.assertEqual(hosts, ['pkg.example.com'])
        self.assertEqual(partial, [])
        self.assertNotIn('secret', hosts[0])
        wild_hosts, wild_partial = ddm.hosts_from_blob('https://*.cdn.example.com/pkg')
        self.assertEqual(wild_hosts, [])
        self.assertEqual(wild_partial, ['wildcard'])
        self.assertEqual(ddm.extra_groups(self.policy(), {'ddm-assets': True}, []), [])

    def test_retired_channel_and_push_stay_off(self):
        current = shields.from_config()
        current['ddm-installs'] = True
        current['ddm-channel'] = True
        current['ddm-push'] = True
        result = shields.apply(current, {'id': 'ddm-channel', 'enabled': True})
        self.assertFalse(result['ddm-channel'])
        self.assertFalse(result['ddm-push'])
        self.assertTrue(result['ddm-installs'])
        loaded = shields.normalize({'ddm-channel': True, 'ddm-push': True, 'retired-shield': True})
        self.assertFalse(loaded['ddm-channel'])
        self.assertFalse(loaded['ddm-push'])
        self.assertNotIn('retired-shield', loaded)

    def test_shared_cdns_are_not_deny_hosts(self):
        self.assertFalse(ddm.usable_host('s3.amazonaws.com'))
        self.assertFalse(ddm.usable_host('d111.cloudfront.net'))
        self.assertFalse(ddm.usable_host('example.akamaihd.net'))
        self.assertFalse(ddm.usable_host('example.fastly.net'))
        self.assertTrue(ddm.usable_host('packages.example.com'))
        self.assertEqual(ddm.extra_groups(self.policy(), {'ddm-installs': True}, ['s3.amazonaws.com']), [])
        groups = ddm.extra_groups(self.policy(), {'ddm-installs': True}, ['packages.example.com'])
        self.assertEqual(groups[0]['hosts'], ['packages.example.com'])
        self.assertNotIn('downloads pause', ddm.UPDATE_WARNING)
        self.assertNotIn('downloads pause', ddm.INSTALL_WARNING)

    def test_snapshot_is_write_once_and_revert_reinserts_only_removed_entries(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'SoftwareUpdateDDMStatePersistence.plist'
            import plistlib
            path.write_bytes(plistlib.dumps({
                'SUCorePersistedStatePolicyFields': {
                    'Declarations': {
                        'plan': {'TargetOSVersion': '27.0.1', 'TargetLocalDateTime': '2026-10-01T20:00:06'},
                        'keep': {'Note': 'leave this'},
                    },
                    'SUCoreDDMDeclarationGlobalSettings': {
                        'automaticallyDownload': True,
                        'automaticallyInstallOSUpdates': True,
                        'automaticallyInstallSystemAndSecurityUpdates': True,
                        'enableGlobalNotifications': True,
                        'enableRapidSecurityResponse': True,
                        'enableRapidSecurityResponseRollback': True,
                        'serializedKeys': ['handle'],
                        'adminInstallRequired': False,
                    },
                }
            }))
            record = {}
            self.assertEqual(ddm.capture_snapshot(record, path), 'snapshotted')
            self.assertNotIn('content_b64', record['softwareupdate'])
            self.assertFalse(record['softwareupdate']['rewrote_ever'])
            path.write_bytes(plistlib.dumps({
                'SUCorePersistedStatePolicyFields': {
                    'Declarations': {
                        'plan': {'TargetOSVersion': '27.0.2', 'TargetLocalDateTime': '2026-10-02T20:00:06'},
                        'keep': {'Note': 'leave this'},
                    },
                    'SUCoreDDMDeclarationGlobalSettings': {
                        'automaticallyDownload': True,
                        'automaticallyInstallOSUpdates': True,
                        'automaticallyInstallSystemAndSecurityUpdates': True,
                        'enableGlobalNotifications': True,
                        'enableRapidSecurityResponse': True,
                        'serializedKeys': ['handle'],
                    },
                }
            }))
            self.assertEqual(ddm.capture_snapshot(record, path), 'snapshotted')
            self.assertFalse(record['softwareupdate']['rewrote_ever'])
            status, rewrote = ddm.hold_software_update(record, path)
            self.assertEqual(status, 'removed')
            self.assertTrue(rewrote)
            kept = plistlib.loads(path.read_bytes())
            fields = kept['SUCorePersistedStatePolicyFields']
            self.assertEqual(list(fields['Declarations']), ['keep'])
            settings = fields['SUCoreDDMDeclarationGlobalSettings']
            self.assertNotIn('automaticallyInstallOSUpdates', settings)
            self.assertNotIn('enableGlobalNotifications', settings)
            self.assertNotIn('serializedKeys', settings)
            self.assertTrue(settings['automaticallyDownload'])
            self.assertTrue(settings['automaticallyInstallSystemAndSecurityUpdates'])
            self.assertTrue(settings['enableRapidSecurityResponse'])
            status, rewrote = ddm.hold_software_update(record, path)
            self.assertEqual(status, 'removed')
            self.assertFalse(rewrote)
            fields['Declarations']['later'] = {'Note': 'daemon wrote this'}
            settings['automaticallyDownload'] = False
            path.write_bytes(plistlib.dumps(kept))
            self.assertIsNone(ddm.revert_software_update(record, path))
            restored = plistlib.loads(path.read_bytes())
            restored_fields = restored['SUCorePersistedStatePolicyFields']
            self.assertEqual(restored_fields['Declarations']['plan']['TargetOSVersion'], '27.0.2')
            self.assertEqual(restored_fields['Declarations']['later']['Note'], 'daemon wrote this')
            self.assertEqual(restored_fields['Declarations']['keep']['Note'], 'leave this')
            restored_settings = restored_fields['SUCoreDDMDeclarationGlobalSettings']
            self.assertFalse(restored_settings['automaticallyDownload'])
            self.assertTrue(restored_settings['automaticallyInstallOSUpdates'])
            self.assertTrue(restored_settings['enableGlobalNotifications'])
            self.assertEqual(restored_settings['serializedKeys'], ['handle'])
            self.assertTrue(restored_settings['automaticallyInstallSystemAndSecurityUpdates'])

    def test_absent_symlink_and_oversize_do_not_remove(self):
        with tempfile.TemporaryDirectory() as temp:
            missing = Path(temp) / 'missing.plist'
            record = {}
            self.assertEqual(ddm.capture_snapshot(record, missing), 'snapshotted')
            self.assertTrue(record['softwareupdate']['absent'])
            status, rewrote = ddm.hold_software_update(record, missing)
            self.assertEqual((status, rewrote), ('restricted', False))
            self.assertFalse(missing.exists())
            import plistlib
            missing.write_bytes(plistlib.dumps({
                'SUCorePersistedStatePolicyFields': {
                    'Declarations': {'plan': {'TargetOSVersion': '27.0.1'}},
                }
            }))
            status, rewrote = ddm.hold_software_update(record, missing)
            self.assertEqual((status, rewrote), ('removed', True))
            self.assertTrue(missing.exists())
            self.assertTrue(record['softwareupdate']['rewrote_ever'])
            self.assertIsNone(ddm.revert_software_update(record, missing))
            self.assertTrue(missing.exists())
            put_back = plistlib.loads(missing.read_bytes())
            self.assertEqual(
                put_back['SUCorePersistedStatePolicyFields']['Declarations']['plan']['TargetOSVersion'],
                '27.0.1')

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

    def test_revert_without_a_rewrite_leaves_the_current_file(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'state.plist'
            path.write_bytes(b'current')
            record = {'softwareupdate': {
                'absent': False,
                'seen': True,
                'rewrote_ever': False,
                'content_b64': 'b2xkLWNvcHk=',
            }}
            self.assertIsNone(ddm.revert_software_update(record, path))
            self.assertEqual(path.read_bytes(), b'current')

    def test_revert_failure_is_reported(self):
        with tempfile.TemporaryDirectory() as temp:
            import plistlib
            removed = plistlib.dumps({
                'declarations': {'plan': {'TargetOSVersion': '27.0.1'}},
                'globals': {},
            })
            record = {'softwareupdate': {
                'absent': False,
                'seen': True,
                'rewrote_ever': True,
                'removed_b64': __import__('base64').b64encode(removed).decode('ascii'),
                'mode': 0o644,
            }}
            error = ddm.revert_software_update(record, temp)
            self.assertTrue(error)
            self.assertIn('removed_b64', record['softwareupdate'])

    def test_public_status_omits_snapshot_bytes(self):
        record = {'softwareupdate': {'content_b64': 'c2VjcmV0', 'absent': False},
                  'softwareupdate_status': 'removed',
                  'types': ['com.apple.configuration.app.managed']}
        status = ddm.public_status({'ddm-update': True}, record, 'off', True)
        self.assertNotIn('c2VjcmV0', str(status))
        self.assertEqual(status['tiles']['ddm-update'], 'removed')
        self.assertNotIn('ddm-channel', status['tiles'])
        self.assertNotIn('ddm-push', status['tiles'])
        installs = ddm.public_status({'ddm-installs': True, 'ddm-assets': True}, {})
        self.assertEqual(installs['tiles']['ddm-installs'], 'partial')
        self.assertEqual(installs['tiles']['ddm-assets'], 'partial')
        self.assertEqual(status['types'], ['com.apple.configuration.app.managed'])


if __name__ == '__main__':
    unittest.main()
