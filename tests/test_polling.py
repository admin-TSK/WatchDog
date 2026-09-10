"""Only temporary fixtures are targeted; no live framework paths or jobs."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('guard', Path(__file__).resolve().parents[1] / 'src/guard.py')
guard = importlib.util.module_from_spec(spec)
spec.loader.exec_module(guard)


class PollingTests(unittest.TestCase):
    def test_reactivation_and_replacement_during_stalled_background_check(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binary = root / 'fixture'
            binary.write_text('original')
            binary.chmod(0o644)
            state = {'version': 1, 'modes': {str(binary): 0o755}, 'jobs': {}}
            stop = threading.Event()
            stalled = threading.Event()
            release = threading.Event()
            timeout_logged = threading.Event()
            cycles = []

            def slow_jobs(current):
                stalled.set()
                release.wait(5)
                with guard.STATE_LOCK:
                    current['jobs']['test/job'] = {'disabled': False}
                    guard.save_state(current)
                raise subprocess.TimeoutExpired(('test-session-discovery',), 10)

            def record_log(message):
                if 'permission checks continue independently' in message:
                    timeout_logged.set()

            def wait_blocked():
                started = time.monotonic()
                while binary.stat().st_mode & 0o111:
                    self.assertLess(time.monotonic() - started, 0.8,
                                    'Permission loop stalled with background checks')
                    time.sleep(0.01)

            with patch.object(guard, 'STATE', root / 'state.json'), \
                 patch.object(guard, 'executables', return_value=[binary]), \
                 patch.object(guard, 'block_jobs', side_effect=slow_jobs), \
                 patch.object(guard, 'log', side_effect=record_log):
                guard.save_state(state)
                background = guard.BackgroundChecks(state, stop, initial_paths=[binary])
                polling = threading.Thread(target=guard.run_permission_checks,
                                           args=(state, background, stop,
                                                 lambda: cycles.append(time.monotonic())))
                background.start()
                polling.start()
                try:
                    self.assertTrue(stalled.wait(1))
                    binary.chmod(0o755)
                    wait_blocked()
                    replacement = root / 'replacement'
                    replacement.write_text('updated')
                    replacement.chmod(0o555)
                    os.replace(replacement, binary)
                    wait_blocked()
                    self.assertFalse(release.is_set())
                    self.assertEqual(binary.read_text(), 'updated')
                    self.assertGreaterEqual(len(cycles), 2)
                    self.assertEqual(guard.PERMISSION_INTERVAL, 0.2)
                    release.set()
                    self.assertTrue(timeout_logged.wait(1))
                    binary.chmod(0o755)
                    wait_blocked()
                    saved = json.loads(guard.STATE.read_text())
                    self.assertEqual(saved['modes'][str(binary)], 0o755)
                    self.assertEqual(saved['jobs']['test/job'], {'disabled': False})
                finally:
                    stop.set()
                    release.set()
                    background.join(2)
                    polling.join(2)
                self.assertFalse(background.is_alive())
                self.assertFalse(polling.is_alive())


if __name__ == '__main__':
    unittest.main()
