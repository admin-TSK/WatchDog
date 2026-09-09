import importlib.util
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('events', Path(__file__).resolve().parents[1] / 'src/event_bridge.py')
events = importlib.util.module_from_spec(spec)
spec.loader.exec_module(events)

class EventTests(unittest.TestCase):
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
