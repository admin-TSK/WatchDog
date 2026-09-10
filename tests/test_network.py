"""Isolated network-policy and PF-generation tests. Never enable live PF."""
import importlib.util
import json
import plistlib
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]


def load(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / 'src' / f'{name}.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


network = load('network')
events = load('event_bridge')
shields = load('shields')


class NetworkTests(unittest.TestCase):
    def policy(self):
        return network.load_policy(ROOT / 'src' / 'network_policy.json')

    def test_schema_and_cidrs(self):
        policy = self.policy()
        self.assertEqual(policy['schema'], 1)
        apns = next(group for group in policy['groups'] if group['id'] == 'apns')
        self.assertIn('17.249.0.0/16', apns['cidrs'])
        self.assertIn('2620:149:a44::/48', apns['cidrs'])
        with self.assertRaises(ValueError):
            network._parse_group({'id': 'empty', 'modes': ['on'], 'ports': [443], 'hosts': [], 'cidrs': []})
        with self.assertRaises(ValueError):
            network._parse_group({'id': 'in', 'modes': ['on'], 'direction': 'in', 'ports': [22], 'hosts': ['example.com']})

    def test_mode_selection_omits_apns_until_yeet(self):
        policy = self.policy()
        on_ids = {group['id'] for group in network.groups_for_mode(policy, 'on')}
        yeet_ids = {group['id'] for group in network.groups_for_mode(policy, 'yeet')}
        self.assertIn('jamf-management', on_ids)
        self.assertNotIn('apns', on_ids)
        self.assertNotIn('apple-enrollment', on_ids)
        self.assertTrue({'apns', 'apple-enrollment'}.issubset(yeet_ids))
        self.assertEqual(network.groups_for_mode(policy, 'off'), [])

    def test_wildcard_matcher(self):
        self.assertTrue(network.wildcard_matches('*.push.apple.com', 'courier.push.apple.com'))
        self.assertFalse(network.wildcard_matches('*.push.apple.com', 'push.apple.com'))
        self.assertFalse(network.wildcard_matches('*.push.apple.com', 'evilpush.apple.com'))

    def test_host_from_url_strips_path(self):
        self.assertEqual(network.host_from_url('https://jss.compnow.com.au:443/mdm/ServerURL?token=secret'),
                         'jss.compnow.com.au')
        self.assertEqual(network.host_from_url('jss.example.com.'), 'jss.example.com')

    def test_discover_management_hosts(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'jamf.plist'
            with open(path, 'wb') as stream:
                plistlib.dump({'jss_url': 'https://jss.compnow.com.au/'}, stream)
            hosts = network.discover_management_hosts(
                jamf_plist=path,
                enrollment_text='MDM server: https://jss.compnow.com.au/checkin\nServerURL = https://mdm.example.net/foo')
            self.assertEqual(hosts, ['jss.compnow.com.au', 'mdm.example.net'])

    def test_generated_rules_always_have_destinations(self):
        destinations = {
            'https_v4': ['203.0.113.10'],
            'https_v6': ['2001:db8::1'],
            'apns_v4': ['17.249.0.0/16'],
            'apns_v6': ['2620:149:a44::/48'],
            'partial': [],
            'stale': [],
            'resolved_count': 1,
        }
        on_text = network.generate_anchor('on', {**destinations, 'apns_v4': [], 'apns_v6': []})
        yeet_text = network.generate_anchor('yeet', destinations)
        self.assertIn(' to <watchdog_https_v4> ', on_text)
        self.assertNotIn('watchdog_apns_v4', on_text)
        self.assertIn('watchdog_apns_v4', yeet_text)
        self.assertIn('5223', yeet_text)
        for text in (on_text, yeet_text):
            for line in text.splitlines():
                if line.startswith('block '):
                    self.assertIn(' out ', line)
                    self.assertIn(' to ', line)
                    self.assertNotRegex(line, r'block drop out proto tcp from any port')

    def test_jra_wildcard_is_partial(self):
        policy = self.policy()
        groups = network.groups_for_mode(policy, 'on')
        result = network.collect_destinations(
            groups, ['jss.compnow.com.au'],
            resolve=lambda host: ({'203.0.113.9'}, set()) if host == 'jss.compnow.com.au' else (set(), set()))
        self.assertIn('jamf-remote-assist', result['partial'])
        self.assertNotIn('*.jra.services.jamfcloud.com', result['stale'])
        self.assertIn('203.0.113.9', result['https_v4'])
        self.assertGreater(result['resolved_count'], 0)

    def test_sync_and_flush_never_flush_all(self):
        policy = ROOT / 'src' / 'network_policy.json'

        def run(args, **kwargs):
            if list(args)[:2] == ['/sbin/pfctl', '-E']:
                return subprocess.CompletedProcess(args, 0, 'Token : 7\nStatus : Enabled\n', '')
            return subprocess.CompletedProcess(args, 0, '', '')

        def resolve(host):
            return {'203.0.113.8'}, set()

        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            conf = root / 'pf.conf'
            conf.write_text('# apple rules\n')
            state = {'pf': {}}
            failures, commands = network.sync(
                'on', root, state, run=run, resolve=resolve, discover=lambda: ['jss.compnow.com.au'],
                pf_conf=conf, policy_path=policy)
            self.assertFalse(failures)
            status = network.read_status(root)
            self.assertIn('jamf-remote-assist', status['partial'])
            self.assertEqual(status['stale'], [])
            self.assertGreater(status['resolved_count'], 0)
            self.assertTrue(any(cmd[:3] == ['/sbin/pfctl', '-a', 'local.watchdog'] for cmd in commands))
            self.assertTrue((root / 'pf.anchor').exists())
            self.assertNotIn('watchdog_apns_v4', (root / 'pf.anchor').read_text())
            self.assertIn('# BEGIN local.watchdog', conf.read_text())
            self.assertTrue(state['pf'].get('conf_marked'))
            self.assertEqual(state['pf'].get('enable_token'), '7')
            self.assertNotIn('enable_token', (root / 'network-status.json').read_text())
            self.assertTrue(any(cmd == ['/sbin/pfctl', '-E'] for cmd in commands))

            failures, commands = network.sync(
                'yeet', root, state, run=run, resolve=resolve, discover=lambda: ['jss.compnow.com.au'],
                pf_conf=conf, policy_path=policy)
            self.assertFalse(failures)
            self.assertFalse(any(cmd[:2] == ['/sbin/pfctl', '-E'] for cmd in commands))
            self.assertIn('watchdog_apns_v4', (root / 'pf.anchor').read_text())

            failures, commands = network.sync(
                'on', root, state, run=run, resolve=resolve, discover=lambda: ['jss.compnow.com.au'],
                pf_conf=conf, policy_path=policy)
            self.assertFalse(failures)
            self.assertNotIn('watchdog_apns_v4', (root / 'pf.anchor').read_text())

            failures, commands = network.flush(root, state, run=run, pf_conf=conf)
            self.assertFalse(failures)
            self.assertNotIn('# BEGIN local.watchdog', conf.read_text())
            self.assertTrue(any(cmd == ['/sbin/pfctl', '-a', 'local.watchdog', '-F', 'all'] for cmd in commands))
            self.assertTrue(any(cmd == ['/sbin/pfctl', '-X', '7'] for cmd in commands))
            self.assertFalse(any(cmd == ['/sbin/pfctl', '-X'] for cmd in commands))
            for cmd in commands:
                self.assertNotEqual(cmd, ['/sbin/pfctl', '-F', 'all'])
                if len(cmd) >= 2 and cmd[0] == '/sbin/pfctl' and cmd[1] == '-X':
                    self.assertEqual(len(cmd), 3)
            self.assertIsNone(state['pf'].get('enable_token'))
            self.assertEqual(network.read_status(root)['mode'], 'off')

    def test_flush_without_record_skips_live_pf(self):
        recorded = []

        def run(args, **kwargs):
            recorded.append(list(args))
            return subprocess.CompletedProcess(args, 0, '', '')

        with tempfile.TemporaryDirectory() as temp:
            failures, commands = network.flush(temp, {}, run=run, pf_conf=Path(temp) / 'missing.conf')
            self.assertEqual(commands, [])
            self.assertFalse(recorded)

    def test_flush_clears_leftover_status_without_undo_flags(self):
        recorded = []

        def run(args, **kwargs):
            recorded.append(list(args))
            return subprocess.CompletedProcess(args, 0, '', '')

        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            conf = root / 'pf.conf'
            conf.write_text('# apple rules\n# BEGIN local.watchdog\nanchor "local.watchdog"\n# END local.watchdog\n')
            (root / 'network-status.json').write_text(json.dumps({
                'mode': 'on', 'anchor_loaded': True, 'resolved_count': 23,
                'partial': ['jamf-remote-assist'], 'stale': [], 'pf_enabled': True
            }))
            failures, commands = network.flush(root, {}, run=run, pf_conf=conf)
            self.assertTrue(any('token' in item.lower() for item in failures))
            self.assertTrue(commands)
            self.assertNotIn('# BEGIN local.watchdog', conf.read_text())
            self.assertTrue(any(cmd == ['/sbin/pfctl', '-s', 'References'] for cmd in recorded))
            self.assertFalse(any(cmd == ['/sbin/pfctl', '-X'] for cmd in recorded))
            self.assertFalse(any(len(cmd) >= 2 and cmd[0] == '/sbin/pfctl' and cmd[1] == '-X' for cmd in recorded))
            self.assertEqual(network.read_status(root)['mode'], 'off')
            self.assertFalse(network.read_status(root)['pf_enabled'])

    def test_enable_token_parsing(self):
        self.assertEqual(network.parse_enable_token('Token : 7\nStatus : Enabled\n'), '7')
        self.assertIsNone(network.parse_enable_token('Status : Enabled\n'))
        table = (
            'TOKENS:\n'
            'PID      Process Name                 TOKEN                    TIMESTAMP\n'
            '618      socketfilterfw               9813589183660731843      0 days 00:03:31\n'
            '1        watchdogd                    42                       0 days 01:00:00\n'
            '501      python3                      99                       0 days 00:01:00\n'
            '880      run-guard                    7                        0 days 00:00:12\n'
        )
        self.assertEqual(network.tokens_from_references(table), ['7'])

    def test_flush_releases_watchdog_reference_without_stored_token(self):
        recorded = []

        def run(args, **kwargs):
            recorded.append(list(args))
            if list(args)[:3] == ['/sbin/pfctl', '-s', 'References']:
                stdout = (
                    'TOKENS:\n'
                    'PID      Process Name                 TOKEN                    TIMESTAMP\n'
                    '618      socketfilterfw               9813589183660731843      0 days 00:03:31\n'
                    '1        watchdogd                    42                       0 days 01:00:00\n'
                    '880      run-guard                    7                        0 days 00:00:12\n'
                )
                return subprocess.CompletedProcess(args, 0, stdout, '')
            return subprocess.CompletedProcess(args, 0, '', '')

        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            conf = root / 'pf.conf'
            conf.write_text('# apple rules\n')
            (root / 'network-status.json').write_text(json.dumps({
                'mode': 'on', 'anchor_loaded': True, 'resolved_count': 1,
                'partial': [], 'stale': [], 'pf_enabled': True
            }))
            failures, commands = network.flush(root, {}, run=run, pf_conf=conf)
            self.assertFalse(failures)
            self.assertIn(['/sbin/pfctl', '-X', '7'], recorded)
            self.assertNotIn(['/sbin/pfctl', '-X', '9813589183660731843'], recorded)
            self.assertNotIn(['/sbin/pfctl', '-X', '42'], recorded)
            self.assertNotIn(['/sbin/pfctl', '-X'], recorded)

    def test_health_includes_network_without_consuming_requests(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / 'state.json').write_text(json.dumps({'modes': {}, 'jobs': {}}))
            inbox = root / 'requests'
            inbox.mkdir()
            (inbox / 'one.json').write_text(json.dumps({'id': 'network', 'mode': 'yeet'}))
            (root / 'network-status.json').write_text(json.dumps({
                'mode': 'on', 'anchor_loaded': True, 'resolved_count': 2, 'partial': ['jamf-remote-assist'],
                'stale': [], 'pf_enabled': True
            }))
            config = {'guard_label': 'test.guard', 'monitor_paths': ['/test/monitor'], 'guard_root': temp}
            result = subprocess.CompletedProcess([], 0, 'state = running\n pid = 123\n', '')
            with patch.object(events.subprocess, 'run', return_value=result), \
                 patch.object(events.processes, 'has_child', return_value=True), \
                 patch.object(events, 'REQUESTS', inbox):
                snapshot = events.health(config)
            self.assertEqual(snapshot['network']['mode'], 'on')
            self.assertEqual(snapshot['network']['partial'], ['jamf-remote-assist'])
            self.assertTrue((inbox / 'one.json').exists())

    def test_network_logs_parse(self):
        event = events.parse_event('Network Yeet.', 'n', 42)
        self.assertEqual(event['title'], 'Network Yeet')
        loaded = events.parse_event('Network rules loaded.', 'r', 42)
        self.assertIn('not a confirmed deny', loaded['detail'])
        self.assertIsNone(events.parse_event('Network hostname partial.', 'h', 42))
        self.assertIsNone(events.parse_event('Network Maybe.', 'x', 42))

    def test_shields_apply_network_mode(self):
        data = shields.apply(shields.DEFAULTS, {'id': 'network', 'mode': 'yeet'})
        self.assertEqual(data['network'], 'yeet')
        data = shields.apply(data, {'id': 'network', 'enabled': False})
        self.assertEqual(data['network'], 'off')
        ignored = shields.apply(data, {'id': 'network', 'mode': 'explode'})
        self.assertEqual(ignored['network'], 'off')


if __name__ == '__main__':
    unittest.main()
