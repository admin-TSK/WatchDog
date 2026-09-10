"""Validate native process lookup against this test and a harmless child."""
import os
from pathlib import Path
import runpy
import subprocess
import unittest

api = runpy.run_path(str(Path(__file__).resolve().parents[1] / 'src/processes.py'))


class ProcessTests(unittest.TestCase):
    def test_native_metadata_and_child_matching(self):
        self.assertEqual(api['C'].sizeof(api['ShortInfo']), 64)
        own = api['info'](os.getpid())
        self.assertEqual(own.pid, os.getpid())
        self.assertEqual(own.ppid, os.getppid())
        self.assertEqual(own.uid, os.getuid())
        self.assertIn(os.getpid(), api['pids']())
        child = subprocess.Popen(['/bin/sleep', '10'])
        try:
            self.assertIn(child.pid, api['pids'](os.getpid()))
            self.assertEqual(api['path'](child.pid), '/bin/sleep')
            self.assertTrue(api['has_child'](os.getpid(), ['/bin/sleep']))
            self.assertFalse(api['has_child'](os.getpid(), ['/does/not/exist']))
            self.assertEqual(api['pids'](child.pid), [])
            self.assertIn(os.stat('/dev/console').st_uid, api['login_uids']())
        finally:
            child.terminate()
            child.wait()


if __name__ == '__main__':
    unittest.main()
