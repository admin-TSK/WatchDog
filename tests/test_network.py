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
        self.assertIn('apple-enrollment', on_ids)
        self.assertNotIn('apns', on_ids)
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
            endpoints = network.discover_management_endpoints(
                jamf_plist=path,
                enrollment_text='MDM server: https://jss.compnow.com.au/checkin\nServerURL = https://mdm.example.net/foo')
            self.assertEqual(endpoints, [
                ('jss.compnow.com.au', 443),
                ('mdm.example.net', 443),
            ])

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
        self.assertIn('203.0.113.9', result['mgmt_v4'])
        self.assertNotIn('203.0.113.9', result['https_v4'])
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

    def test_state_kill_timeout_does_not_fail_loaded_rules(self):
        policy = ROOT / 'src' / 'network_policy.json'
        kills = []

        def run(args, **kwargs):
            argv = list(args)
            if argv[:2] == ['/sbin/pfctl', '-E']:
                return subprocess.CompletedProcess(args, 0, 'Token : 7\nStatus : Enabled\n', '')
            if argv[:2] == ['/sbin/pfctl', '-k']:
                kills.append(argv)
                raise subprocess.TimeoutExpired(args, kwargs.get('timeout', 1))
            return subprocess.CompletedProcess(args, 0, '', '')

        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            conf = root / 'pf.conf'
            conf.write_text('# apple rules\n')
            failures, commands = network.sync(
                'on', root, {'pf': {}}, run=run, resolve=lambda host: ({'203.0.113.8'}, set()),
                discover=lambda: ['jss.example.com'], pf_conf=conf, policy_path=policy)
            self.assertEqual(failures, [network.MGMT_KILL_WARNING])
            self.assertEqual(network.read_status(root)['mode'], 'on')
            self.assertTrue(network.read_status(root)['anchor_loaded'])
            self.assertEqual(len(kills), 1)
            self.assertTrue(any(cmd[:3] == ['/sbin/pfctl', '-a', 'local.watchdog'] for cmd in commands))
            event = events.parse_event('PROTECTION ERROR: ' + network.MGMT_KILL_WARNING, 'k', 42)
            self.assertEqual(event['kind'], 'warning')
            self.assertEqual(event['title'], 'Existing Jamf connections were not reset')

    def test_dns_refresh_skips_state_kill(self):
        policy = ROOT / 'src' / 'network_policy.json'

        def run(args, **kwargs):
            if list(args)[:2] == ['/sbin/pfctl', '-E']:
                return subprocess.CompletedProcess(args, 0, 'Token : 7\nStatus : Enabled\n', '')
            return subprocess.CompletedProcess(args, 0, '', '')

        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            conf = root / 'pf.conf'
            conf.write_text('# apple rules\n')
            failures, commands = network.sync(
                'on', root, {'pf': {}}, run=run, resolve=lambda host: ({'203.0.113.8'}, set()),
                discover=lambda: ['jss.example.com'], pf_conf=conf, policy_path=policy,
                kill_states=False)
            self.assertFalse(failures)
            self.assertFalse(any(cmd[:2] == ['/sbin/pfctl', '-k'] for cmd in commands))

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

    def test_state_kill_skips_cidrs_and_caps_unicast(self):
        targets, management = network.state_kill_targets({
            'mgmt_v4': ['203.0.113.8', '203.0.113.0/24'],
            'https_v4': ['198.51.100.4'],
            'https_v6': [],
            'apns_v4': ['17.249.0.0/16'],
            'apns_v6': ['2620:149:a44::/48'],
        })
        self.assertEqual(targets[0], '203.0.113.8')
        self.assertIn('198.51.100.4', targets)
        self.assertNotIn('203.0.113.0/24', targets)
        self.assertFalse(any('/' in addr for addr in targets))
        self.assertEqual(management, {'203.0.113.8'})

        kills = []

        def run(args, **kwargs):
            argv = list(args)
            if argv[:2] == ['/sbin/pfctl', '-E']:
                return subprocess.CompletedProcess(args, 0, 'Token : 7\nStatus : Enabled\n', '')
            if argv[:2] == ['/sbin/pfctl', '-k']:
                kills.append(argv)
            return subprocess.CompletedProcess(args, 0, '', '')

        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            conf = root / 'pf.conf'
            conf.write_text('# apple rules\n')
            failures, commands = network.sync(
                'yeet', root, {'pf': {}}, run=run,
                resolve=lambda host: ({'203.0.113.8'}, set()),
                discover=lambda: ['jss.example.com'], pf_conf=conf,
                policy_path=ROOT / 'src' / 'network_policy.json')
            self.assertFalse(failures)
            self.assertTrue(kills)
            self.assertFalse(any('/' in cmd[-1] for cmd in kills if cmd[:2] == ['/sbin/pfctl', '-k']))
            self.assertLessEqual(len(kills), network.STATE_KILL_CAP)

    def test_empty_running_rules_reloads_pf_conf(self):
        recorded = []

        def run(args, **kwargs):
            recorded.append(list(args))
            if list(args)[:2] == ['/sbin/pfctl', '-E']:
                return subprocess.CompletedProcess(args, 0, 'Token : 7\nStatus : Enabled\n', '')
            if list(args)[:4] == ['/sbin/pfctl', '-a', 'local.watchdog', '-s']:
                return subprocess.CompletedProcess(args, 0, '', '')
            return subprocess.CompletedProcess(args, 0, '', '')

        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            conf = root / 'pf.conf'
            conf.write_text('# apple rules\n')
            state = {'pf': {}}
            policy = ROOT / 'src' / 'network_policy.json'
            network.sync(
                'on', root, state, run=run, resolve=lambda host: ({'203.0.113.8'}, set()),
                discover=lambda: ['jss.example.com'], pf_conf=conf, policy_path=policy,
                kill_states=False)
            recorded.clear()
            network.sync(
                'on', root, state, run=run, resolve=lambda host: ({'203.0.113.8'}, set()),
                discover=lambda: ['jss.example.com'], pf_conf=conf, policy_path=policy,
                kill_states=False)
            self.assertTrue(any(cmd[:2] == ['/sbin/pfctl', '-f'] for cmd in recorded))
            self.assertTrue(any(cmd[:4] == ['/sbin/pfctl', '-a', 'local.watchdog', '-s'] for cmd in recorded))

    def test_load_anchor_enables_pf_when_disabled(self):
        loads = []

        def run(args, **kwargs):
            argv = list(args)
            if argv[:4] == ['/sbin/pfctl', '-a', 'local.watchdog', '-s']:
                return subprocess.CompletedProcess(args, 0, 'block drop out proto tcp from any to <watchdog_https_v4> port { 443 }\n', '')
            if argv[:2] == ['/sbin/pfctl', '-E']:
                return subprocess.CompletedProcess(args, 0, 'Token : 11\nStatus : Enabled\n', '')
            if argv[:3] == ['/sbin/pfctl', '-a', 'local.watchdog'] and '-f' in argv:
                loads.append(argv)
                if len(loads) == 1:
                    return subprocess.CompletedProcess(args, 1, '', 'pfctl: /dev/pf: Device not configured\n')
            return subprocess.CompletedProcess(args, 0, '', '')

        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            conf = root / 'pf.conf'
            conf.write_text(
                '# apple rules\n# BEGIN local.watchdog\nanchor "local.watchdog"\n'
                f'load anchor "local.watchdog" from "{root / "pf.anchor"}"\n# END local.watchdog\n')
            state = {'pf': {'enable_token': '9', 'enabled_incremented': True, 'conf_marked': True}}
            failures, commands = network.sync(
                'on', root, state, run=run, resolve=lambda host: ({'203.0.113.8'}, set()),
                discover=lambda: ['jss.example.com'], pf_conf=conf,
                policy_path=ROOT / 'src' / 'network_policy.json', kill_states=False)
            self.assertFalse(failures)
            self.assertGreaterEqual(len(loads), 2)
            self.assertIn(['/sbin/pfctl', '-E'], commands)
            self.assertEqual(state['pf']['enable_token'], '11')
            self.assertTrue(network.read_status(root)['anchor_loaded'])

    def test_on_includes_enrollment_excludes_apns(self):
        groups = network.groups_for_mode(self.policy(), 'on')
        destinations = network.collect_destinations(
            groups, ['jss.example.com'],
            resolve=lambda host: ({'203.0.113.20'}, set()),
            endpoints=[('jss.example.com', 443)])
        text = network.generate_anchor('on', destinations)
        self.assertIn('203.0.113.20', text)
        self.assertNotIn('watchdog_apns', text)
        self.assertNotIn('5223', text)

    def test_jss_custom_port_is_management_only(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'jamf.plist'
            with open(path, 'wb') as stream:
                plistlib.dump({'jss_url': 'https://jss.example.com:8443/'}, stream)
            endpoints = network.discover_management_endpoints(jamf_plist=path)
            self.assertEqual(endpoints, [('jss.example.com', 8443)])
            destinations = network.collect_destinations(
                network.groups_for_mode(self.policy(), 'on'),
                ['jss.example.com'],
                resolve=lambda host: ({'203.0.113.30'}, set()) if host == 'jss.example.com' else (set(), set()),
                endpoints=endpoints)
            self.assertIn('203.0.113.30', destinations['mgmt_v4'])
            self.assertNotIn('203.0.113.30', destinations['https_v4'])
            self.assertIn(8443, destinations['mgmt_ports'])
            text = network.generate_anchor('on', destinations)
            self.assertIn('8443', text)
            for line in text.splitlines():
                if line.startswith('block ') and 'watchdog_https_' in line:
                    self.assertNotIn('8443', line)

    def test_profiles_timeout_returns_empty_and_is_not_logged(self):
        def run(args, **kwargs):
            raise subprocess.TimeoutExpired(args, kwargs.get('timeout', 3))

        self.assertEqual(network.enrollment_text_from_profiles(run=run), '')
        hosts = network.discover_management_hosts(
            jamf_plist=Path('/tmp/missing-jamf-plist'),
            enrollment_text='')
        self.assertEqual(hosts, [])

    def test_shields_apply_network_mode(self):
        data = shields.apply(shields.DEFAULTS, {'id': 'network', 'mode': 'yeet'})
        self.assertEqual(data['network'], 'yeet')
        data = shields.apply(data, {'id': 'network', 'enabled': False})
        self.assertEqual(data['network'], 'off')
        ignored = shields.apply(data, {'id': 'network', 'mode': 'explode'})
        self.assertEqual(ignored['network'], 'off')


if __name__ == '__main__':
    unittest.main()
