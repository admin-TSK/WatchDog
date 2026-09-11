import importlib.util
import re
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('targets', ROOT / 'src' / 'targets.py')
targets = importlib.util.module_from_spec(spec)
spec.loader.exec_module(targets)


def c_strings(source, begin, end):
    block = source.split(begin, 1)[1].split(end, 1)[0]
    return tuple(re.findall(r'"([^"]*)"', block))


class TargetParityTests(unittest.TestCase):
    def test_python_and_c_lists_match(self):
        source = (ROOT / 'src' / 'watchdog.c').read_text()
        self.assertEqual(targets.EXACT_PATHS, c_strings(source, 'WATCHDOG_TARGETS_EXACT', 'WATCHDOG_TARGETS_EXACT_END'))
        self.assertEqual(targets.PREFIXES, c_strings(source, 'WATCHDOG_TARGETS_PREFIX', 'WATCHDOG_TARGETS_PREFIX_END'))
        self.assertEqual(targets.CONNECT_EXACT_PATHS, c_strings(source, 'WATCHDOG_TARGETS_CONNECT_EXACT', 'WATCHDOG_TARGETS_CONNECT_EXACT_END'))
        self.assertEqual(targets.CONNECT_PREFIXES, c_strings(source, 'WATCHDOG_TARGETS_CONNECT_PREFIX', 'WATCHDOG_TARGETS_CONNECT_PREFIX_END'))
        self.assertEqual(targets.EXCLUDE_PREFIXES, c_strings(source, 'WATCHDOG_TARGETS_EXCLUDE', 'WATCHDOG_TARGETS_EXCLUDE_END'))
        self.assertEqual(targets.SIGNATURE_ALLOW, c_strings(source, 'WATCHDOG_TARGETS_SIGNATURE_ALLOW', 'WATCHDOG_TARGETS_SIGNATURE_ALLOW_END'))
        self.assertEqual(targets.SIGNATURE_CONNECT, c_strings(source, 'WATCHDOG_TARGETS_SIGNATURE_CONNECT', 'WATCHDOG_TARGETS_SIGNATURE_CONNECT_END'))
        self.assertEqual(targets.SIGNATURE_DENY, c_strings(source, 'WATCHDOG_TARGETS_SIGNATURE_DENY', 'WATCHDOG_TARGETS_SIGNATURE_DENY_END'))

    def test_jamf_helper_and_usr_local_bin_are_in_scope(self):
        self.assertIn('/usr/local/bin/jamf', targets.EXACT_PATHS)
        self.assertIn('/Applications/Self Service+.app/', targets.PREFIXES)
        self.assertIn('/Applications/Self Service+.app', targets.WALK_ROOTS)
        self.assertTrue(any(p.startswith('/Library/Application Support/JAMF/') for p in targets.PREFIXES))
        self.assertFalse(any(Path(p).name == 'Jamf.app' for p in targets.PREFIXES))

    def test_exclusions(self):
        self.assertTrue(targets.excluded('/Applications/jamfcheck.app/Contents/MacOS/jamfcheck'))
        self.assertTrue(targets.excluded('/Applications/Jamf Compliance Editor.app/Contents/MacOS/x'))
        self.assertTrue(targets.excluded('/Library/Application Support/JamfProtect/bin/JamfProtect'))
        self.assertTrue(targets.excluded('/Library/Security/SecurityAgentPlugins/JamfConnectLogin.bundle/x'))
        self.assertFalse(targets.excluded('/Library/Application Support/JAMF/bin/jamfHelper.app/Contents/MacOS/jamfHelper'))

    def test_job_labels(self):
        self.assertTrue(targets.job_label('com.jamfsoftware.task.1'))
        self.assertTrue(targets.job_label('com.jamfsoftware.selfservice.mac'))
        self.assertTrue(targets.job_label('com.jamf.appinstallers.GoogleChrome'))
        self.assertTrue(targets.job_label('com.jamf.management.startup'))
        self.assertTrue(targets.job_label('com.jamf.management.agent'))
        self.assertFalse(targets.job_label('com.jamf.connect'))
        self.assertTrue(targets.job_label('com.jamf.connect', block_connect=True))
        self.assertTrue(targets.job_label('com.jamf.connect.useragent', block_connect=True))
        self.assertFalse(targets.job_label('com.jamf.protect.agent'))
        self.assertFalse(targets.job_label('com.jamf.protect.agent', block_connect=True))

    def test_signature_allow_and_deny(self):
        self.assertTrue(targets.signature_allowed('com.jamfsoftware.jamf'))
        self.assertTrue(targets.signature_allowed('com.jamf.management.daemon'))
        self.assertFalse(targets.signature_allowed('com.jamf.connect.login'))
        self.assertTrue(targets.signature_allowed('com.jamf.connect.login', block_connect=True))
        self.assertFalse(targets.signature_allowed('com.jamf.protect.agent'))
        self.assertFalse(targets.signature_allowed('com.jamf.protect.agent', block_connect=True))
        self.assertFalse(targets.signature_allowed('com.txhaflaire.jamfcheck'))
        binary = ROOT / 'build' / 'watchdog'
        allow = subprocess.run([str(binary), '--test-identifier', 'com.jamfsoftware.jamf'], capture_output=True, text=True)
        deny = subprocess.run([str(binary), '--test-identifier', 'com.jamf.protect.agent'], capture_output=True, text=True)
        connect_off = subprocess.run([str(binary), '--test-identifier', 'com.jamf.connect'], capture_output=True, text=True)
        connect_on = subprocess.run([str(binary), '--block-connect', '--test-identifier', 'com.jamf.connect'], capture_output=True, text=True)
        self.assertEqual(allow.returncode, 0)
        self.assertEqual(allow.stdout.strip(), 'allow')
        self.assertEqual(deny.returncode, 1)
        self.assertEqual(deny.stdout.strip(), 'deny')
        self.assertEqual(connect_off.returncode, 1)
        self.assertEqual(connect_on.returncode, 0)


if __name__ == '__main__':
    unittest.main()
