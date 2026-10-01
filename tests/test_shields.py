"""Isolated shield toggle tests. No live Jamf paths."""
import importlib.util
import json
import subprocess
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]


def load(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / 'src' / f'{name}.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


shields = load('shields')
events = load('event_bridge')
guard = load('guard')


class ShieldTests(unittest.TestCase):
    def test_defaults_and_apply(self):
        data = shields.from_config({'sticky_block': True, 'block_connect': False})
        self.assertTrue(data['permissions'])
        self.assertTrue(data['sticky'])
        self.assertFalse(data['connect'])
        self.assertEqual(data['network'], 'off')
        data = shields.apply(data, {'id': 'monitor', 'enabled': False})
        self.assertFalse(data['monitor'])
        self.assertTrue(data['permissions'])
        ignored = shields.apply(data, {'id': 'unknown', 'enabled': True})
        self.assertEqual(ignored, data)

    def test_round_trip_file(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'shields.json'
            saved = shields.save(path, {'permissions': False, 'connect': True})
            loaded = shields.load(path)
            self.assertFalse(loaded['permissions'])
            self.assertTrue(loaded['connect'])
            self.assertTrue(saved['jobs'])

    def test_consume_applies_drop_files(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            inbox = root / 'requests'
            inbox.mkdir()
            (inbox / 'one.json').write_text(json.dumps({'id': 'jobs', 'enabled': False}))
            (inbox / 'two.json').write_text(json.dumps({'id': 'sticky', 'enabled': True}))
            (inbox / 'bad.json').write_text('not json')
            with patch.object(events, 'REQUESTS', inbox):
                result = events.consume_shield_requests(root)
            self.assertFalse(result['jobs'])
            self.assertTrue(result['sticky'])
            self.assertTrue((root / 'shields.json').exists())
            self.assertEqual(list(inbox.glob('*.json')), [])

    def test_shield_log_is_parsed(self):
        event = events.parse_event('Shield permissions off.', 's', 42)
        self.assertEqual(event['kind'], 'shield')
        self.assertEqual(event['title'], 'Permissions shield off')
        self.assertIsNone(events.parse_event('Shield mystery on.', 'x', 42))

    def test_permissions_off_restores_and_skips_block(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binary = root / 'fixture'
            binary.write_text('x')
            binary.chmod(0o644)
            state = {'version': 2, 'modes': {str(binary): 0o755}, 'jobs': {}, 'flags': {}}
            stop = threading.Event()

            class Paths:
                def paths(self):
                    return [binary]

            payload = dict(shields.DEFAULTS)
            payload['permissions'] = False
            (root / 'shields.json').write_text(json.dumps(payload))
            guard.SHIELDS = dict(shields.DEFAULTS)
            guard.SHIELDS_READY = True
            try:
                with patch.object(guard, 'STATE', root / 'state.json'), \
                     patch.object(guard, 'block_modes') as blocked, \
                     patch.object(guard, 'restore_modes', return_value=[]) as restored, \
                     patch.object(guard, 'log'):
                    polling = threading.Thread(
                        target=guard.run_permission_checks,
                        args=(state, Paths(), stop))
                    polling.start()
                    time.sleep(0.2)
                    stop.set()
                    polling.join(2)
                    self.assertFalse(polling.is_alive())
                    restored.assert_called()
                    blocked.assert_not_called()
            finally:
                stop.set()
                guard.SHIELDS = dict(shields.DEFAULTS)
                guard.SHIELDS_READY = False

    def test_network_refresh_does_not_log_expected_partial(self):
        status = {'partial': ['jamf-remote-assist'], 'stale': []}
        with patch.object(guard.network, 'sync', return_value=([], [])), \
             patch.object(guard.network, 'read_status', return_value=status), \
             patch.object(guard, 'save_state'), \
             patch.object(guard, 'log') as logged:
            self.assertEqual(guard.sync_network('on', {}, announce=True), [])
            self.assertEqual(guard.sync_network('on', {}, announce=False), [])
        messages = [call.args[0] for call in logged.call_args_list]
        self.assertEqual(messages.count('Network rules loaded.'), 1)
        self.assertNotIn('Network hostname partial.', messages)
        stale = {'partial': ['jamf-remote-assist'], 'stale': ['missing.example']}
        with patch.object(guard.network, 'sync', return_value=([], [])), \
             patch.object(guard.network, 'read_status', return_value=stale), \
             patch.object(guard, 'save_state'), \
             patch.object(guard, 'log') as logged:
            self.assertEqual(guard.sync_network('on', {}, announce=True), [])
        self.assertIn('Network resolution failed.', [call.args[0] for call in logged.call_args_list])

    def test_network_sync_follows_applied_mode_not_refresh_edge(self):
        now = 1000.0
        needed, announce = guard.should_sync_network('on', 'off', 0.0, now)
        self.assertTrue(needed)
        self.assertTrue(announce)
        needed, announce = guard.should_sync_network('on', 'on', now, now)
        self.assertFalse(needed)
        needed, announce = guard.should_sync_network('on', 'on', now, now + 60)
        self.assertTrue(needed)
        self.assertFalse(announce)
        needed, announce = guard.should_sync_network('off', 'on', now, now)
        self.assertTrue(needed)
        self.assertTrue(announce)
        needed, announce = guard.should_sync_network('off', 'off', 0.0, now)
        self.assertFalse(needed)

    def test_jobs_off_survives_a_consumed_refresh(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            payload = dict(shields.DEFAULTS)
            payload['jobs'] = False
            (root / 'shields.json').write_text(json.dumps(payload))
            guard.SHIELDS = dict(shields.DEFAULTS)
            guard.SHIELDS_READY = True
            state = {'version': 2, 'modes': {}, 'jobs': {}, 'flags': {}, 'pf': {}, 'ddm': {}}
            try:
                with patch.object(guard, 'STATE', root / 'state.json'), \
                     patch.object(guard, 'restore_jobs', return_value=[]) as restored, \
                     patch.object(guard, 'block_jobs', return_value=[]) as blocked, \
                     patch.object(guard, 'release_connect', return_value=[]), \
                     patch.object(guard, 'log'):
                    guard.refresh_shields()
                    background = guard.BackgroundChecks(state, threading.Event())
                    current, _previous = guard.refresh_shields()
                    background.apply_shield_edges(current)
                restored.assert_called_once()
                blocked.assert_not_called()
            finally:
                guard.SHIELDS = dict(shields.DEFAULTS)
                guard.SHIELDS_READY = False

    def test_clear_sticky_restores_only_recorded_flags(self):
        state = {'modes': {'/a': 0o755, '/b': 0o755}, 'flags': {'/a': 2}}
        with patch.object(guard, '_set_flags') as setter:
            self.assertEqual(guard.clear_sticky(state), [])
        setter.assert_called_once_with(Path('/a'), 2)

    def test_restore_flushes_packet_filter_when_revert_fails(self):
        state = {'modes': {}, 'jobs': {}, 'flags': {}, 'pf': {}, 'ddm': {}}
        with patch.object(guard, 'restore_modes', return_value=[]), \
             patch.object(guard, 'restore_jobs', return_value=[]), \
             patch.object(guard, 'revert_ddm', return_value=['snapshot failed']), \
             patch.object(guard, 'sync_network', return_value=[]) as sync:
            failures = guard.restore(state)
        self.assertEqual(failures, ['snapshot failed'])
        sync.assert_called_once()
        self.assertEqual(sync.call_args.args[0], 'off')
        self.assertFalse(sync.call_args.kwargs['use_shields'])

    def test_connect_off_restores_and_forgets_only_connect(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binary = root / 'connect-bin'
            binary.write_text('x')
            binary.chmod(0o644)
            jamf = root / 'jamf'
            jamf.write_text('x')
            jamf.chmod(0o644)
            state = {
                'version': 2,
                'modes': {str(binary): 0o755, str(jamf): 0o755},
                'jobs': {
                    'system/com.jamf.connect': {'disabled': False, 'loaded': False, 'path': None},
                    'system/com.jamf.management.daemon': {
                        'disabled': False, 'loaded': True, 'path': None,
                    },
                },
                'flags': {},
                'pf': {},
                'ddm': {},
            }
            with patch.object(guard, 'STATE', root / 'state.json'), \
                 patch.object(guard.targets, 'connect_path', side_effect=lambda path: str(path) == str(binary)), \
                 patch.object(guard, 'command', return_value=subprocess.CompletedProcess([], 0, '', '')), \
                 patch.object(guard, 'log'):
                self.assertEqual(guard.release_connect(state), [])
            self.assertNotIn(str(binary), state['modes'])
            self.assertIn(str(jamf), state['modes'])
            self.assertNotIn('system/com.jamf.connect', state['jobs'])
            self.assertIn('system/com.jamf.management.daemon', state['jobs'])
            self.assertEqual(binary.stat().st_mode & 0o777, 0o755)

    def test_drop_ignores_other_owners_and_caps_a_pass(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            inbox = root / 'requests'
            inbox.mkdir()
            (inbox / 'one.json').write_text(json.dumps({'id': 'jobs', 'enabled': False}))
            with patch.object(events, 'REQUESTS', inbox), \
                 patch.object(events, 'request_owner_allowed', return_value=False):
                result = events.consume_shield_requests(root)
            self.assertTrue(result['jobs'])
            self.assertEqual(list(inbox.glob('*.json')), [])
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            inbox = root / 'requests'
            inbox.mkdir()
            for index in range(events.MAX_REQUESTS + 8):
                (inbox / f'{index:03d}.json').write_text(json.dumps({'id': 'sticky', 'enabled': True}))
            with patch.object(events, 'REQUESTS', inbox), \
                 patch.object(events, 'request_owner_allowed', return_value=True):
                result = events.consume_shield_requests(root)
            self.assertTrue(result['sticky'])
            self.assertEqual(len(list(inbox.glob('*.json'))), 8)


if __name__ == '__main__':
    unittest.main()
