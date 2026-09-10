"""Isolated shield toggle tests. No live Jamf paths."""
import importlib.util
import json
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


if __name__ == '__main__':
    unittest.main()
