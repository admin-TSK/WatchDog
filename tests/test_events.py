import importlib.util
from pathlib import Path
import tempfile
import unittest
import json
import subprocess
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('events', Path(__file__).resolve().parents[1] / 'src/event_bridge.py')
events = importlib.util.module_from_spec(spec)
spec.loader.exec_module(events)

class EventTests(unittest.TestCase):
    def test_only_confirmed_recovery_resolves_earlier_session_warnings(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'log'
            warning = "PROTECTION ERROR: TimeoutExpired(('/bin/ps', '-axo', 'uid=,comm='), 10)"
            path.write_text('2026-09-10 09:00:00 ' + warning + '\n2026-09-10 09:00:01 PROTECTION ERROR: Could not disable job\n')
            feed = events.Feed()
            feed.read(path, 1)
            self.assertNotIn('resolved_at', feed.events[0])
            with path.open('a') as stream:
                stream.write('2026-09-10 09:00:02 Session discovery healthy: native process lookup.\n')
            # An older reader may have advanced past the unfamiliar recovery line
            # while the guard and reader were being upgraded separately.
            old_saved = feed.saved()
            old_saved['parser_version'] = 2
            old_saved['cursor'] = {**old_saved['cursor'], 'offset': path.stat().st_size}
            migrated = events.Feed(old_saved)
            migrated.read(path, 2)
            self.assertIn('resolved_at', migrated.events[0])
            feed.read(path, 2)
            self.assertIn('resolved_at', feed.events[0])
            self.assertNotIn('resolved_at', feed.events[1])
            self.assertEqual(feed.action_total, 2)
            original_id = feed.events[0]['id']
            restored = events.Feed(feed.saved())
            with path.open('a') as stream:
                stream.write('2026-09-10 09:00:03 ' + warning + '\n')
            restored.read(path, 3)
            self.assertEqual(restored.events[0]['id'], original_id)
            self.assertIn('resolved_at', restored.events[0])
            self.assertNotIn('resolved_at', restored.events[-1])
            self.assertEqual(restored.action_total, 3)

    def test_timeout_history_is_reclassified_without_replay(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'log'
            path.write_text("2026-09-10 09:58:59 PROTECTION ERROR: TimeoutExpired(('/bin/ps', '-axo', 'uid=,comm='), 10)\n")
            feed = events.Feed()
            feed.read(path, 42)
            self.assertEqual(feed.events[0]['kind'], 'warning')
            saved = feed.saved()
            saved.pop('parser_version')
            saved['events'][0].update(kind='error', title='A protection action failed', detail='Old generic message')
            original_id = saved['events'][0]['id']
            original_cursor = dict(saved['cursor'])
            restored = events.Feed(saved)
            restored.read(path, 43)
            self.assertEqual(restored.events[0]['title'], 'Session check timed out')
            self.assertEqual(restored.events[0]['id'], original_id)
            self.assertEqual(restored.cursor, original_cursor)
            self.assertEqual(restored.action_total, 1)
            restored.read(path, 44)
            self.assertEqual(len(restored.events), 1)
            real = events.parse_event('PROTECTION ERROR: Could not disable system/com.jamf.management.daemon', 'real', 45)
            self.assertEqual(real['kind'], 'error')

    def test_health_checks_every_recorded_executable_without_ps(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            binary = root / 'component'
            binary.write_text('fixture')
            binary.chmod(0o755)
            (root / 'state.json').write_text(json.dumps({'modes': {str(binary): 0o755}}))
            config = {'guard_label': 'test.guard', 'monitor_paths': ['/test/monitor'], 'guard_root': temp}
            result = subprocess.CompletedProcess([], 0, 'state = running\n pid = 123\n', '')
            with patch.object(events.subprocess, 'run', return_value=result) as command, patch.object(events.processes, 'has_child', return_value=True):
                snapshot = events.health(config)
                self.assertFalse(snapshot['execution_blocked'])
                self.assertTrue(snapshot['shields']['permissions'])
                self.assertFalse(snapshot['shields']['connect'])
                self.assertEqual(command.call_args.args[0][0], '/bin/launchctl')
                self.assertEqual(command.call_count, 1)

    def test_allowlist_and_redaction(self):
        event = events.parse_event('Execution blocked: /private/user/JamfDaemon', 'a', 42)
        self.assertEqual(event['detail'], 'JamfDaemon')
        self.assertNotIn('/private', str(event))
        self.assertIsNone(events.parse_event('secret unrelated log line', 'b', 42))
        self.assertIsNone(events.parse_event('Launch job disabled: system/unrelated.job', 'c', 42))
        self.assertIsNone(events.parse_event('Launch job disabled: system/com.jamf.protect.agent', 'p', 42))
        connect = events.parse_event('Launch job disabled: gui/501/com.jamf.connect.useragent', 'e', 42)
        self.assertEqual(connect['detail'], 'com.jamf.connect.useragent')
        error = events.parse_event('PROTECTION ERROR: secret private path', 'd', 42)
        self.assertNotIn('secret', str(error))
        shield = events.parse_event('Shield monitor off.', 's', 42)
        self.assertEqual(shield['kind'], 'shield')
        self.assertEqual(shield['title'], 'Monitor shield off')
        self.assertIsNone(events.parse_event('Shield mystery on.', 'x', 42))

    def test_process_time_not_invented_for_old_native_logs(self):
        line = 'Killed framework process or observed descendant PID 123.'
        self.assertIsNone(events.parse_event(line, 'a', 42, historical=True)['timestamp'])
        self.assertEqual(events.parse_event(line, 'b', 42)['timestamp'], 42)

    def test_partial_lines_restart_and_rotation(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'log'
            path.write_text('Execution blocked: /example/jamf\nKilled framework process or observed descendant PID ')
            feed = events.Feed()
            feed.read(path, 42)
            self.assertEqual(feed.action_total, 1)
            restored = events.Feed(feed.saved())
            with path.open('a') as f: f.write('123.\n')
            restored.read(path, 43)
            self.assertEqual(restored.process_total, 1)
            self.assertEqual(restored.action_total, 2)
            restored.read(path, 44)
            self.assertEqual(restored.action_total, 2)
            path.rename(Path(temp) / 'old')
            path.write_text('Execution blocked: /example/JamfAgent\n')
            restored.read(path, 45)
            self.assertEqual(restored.action_total, 3)

    def test_heal_guard_is_rate_limited(self):
        config = {'guard_label': 'test.guard'}
        with patch.object(events.subprocess, 'run') as command, patch.object(Path, 'exists', return_value=True):
            stamp, attempted = events.heal_guard(config, 100, 90, minimum=60)
            self.assertFalse(attempted)
            self.assertEqual(stamp, 90)
            command.assert_not_called()
            stamp, attempted = events.heal_guard(config, 160, 90, minimum=60)
            self.assertTrue(attempted)
            self.assertEqual(stamp, 160)
            self.assertEqual(command.call_args.args[0][1], 'bootstrap')

if __name__ == '__main__': unittest.main()
