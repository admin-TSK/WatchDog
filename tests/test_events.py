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
                self.assertFalse(events.health(config)['execution_blocked'])
                self.assertEqual(command.call_args.args[0][0], '/bin/launchctl')
                self.assertEqual(command.call_count, 1)

    def test_allowlist_and_redaction(self):
        event = events.parse_event('Execution blocked: /private/user/JamfDaemon', 'a', 42)
        self.assertEqual(event['detail'], 'JamfDaemon')
        self.assertNotIn('/private', str(event))
        self.assertIsNone(events.parse_event('secret unrelated log line', 'b', 42))
        self.assertIsNone(events.parse_event('Launch job disabled: system/unrelated.job', 'c', 42))
        error = events.parse_event('PROTECTION ERROR: secret private path', 'd', 42)
        self.assertNotIn('secret', str(error))

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

if __name__ == '__main__': unittest.main()
