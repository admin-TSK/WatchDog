"""Single source of truth for WatchDog path, launch-job, and signing matches.

Keep the marked string lists in src/watchdog.c identical. tests/test_targets.py
compares them. Jamf Protect and non-Jamf lookalikes are never matched.
Jamf Connect is opt-in: never rewrite authorizationdb or touch login-window
SecurityAgentPlugins.
"""
import os
import stat
from pathlib import Path

# WATCHDOG_TARGETS_EXACT
EXACT_PATHS = (
    '/usr/local/jamf/bin/jamf',
    '/usr/local/bin/jamf',
    '/usr/local/jamf/bin/jamfAgent',
)
# WATCHDOG_TARGETS_EXACT_END

# WATCHDOG_TARGETS_PREFIX
PREFIXES = (
    '/Library/Application Support/JAMF/',
    '/Library/Application Support/JamfAppInstallers/',
    '/Applications/Self Service.app/',
    '/Applications/Jamf Self Service.app/',
)
# WATCHDOG_TARGETS_PREFIX_END

# WATCHDOG_TARGETS_CONNECT_EXACT
CONNECT_EXACT_PATHS = (
    '/usr/local/bin/authchanger',
)
# WATCHDOG_TARGETS_CONNECT_EXACT_END

# WATCHDOG_TARGETS_CONNECT_PREFIX
CONNECT_PREFIXES = (
    '/Applications/Jamf Connect.app/',
    '/Applications/Jamf Connect Configuration.app/',
    '/Library/Application Support/JamfConnect/',
)
# WATCHDOG_TARGETS_CONNECT_PREFIX_END

# WATCHDOG_TARGETS_EXCLUDE
EXCLUDE_PREFIXES = (
    '/Applications/jamfcheck.app/',
    '/Applications/Jamf Compliance Editor.app/',
    '/Library/Application Support/JamfProtect/',
    '/Library/Management/AppAutoPatch/',
    '/Library/Application Support/WatchDog/',
    '/Library/Application Support/Jamf Test Blocker/',
    '/Library/Security/SecurityAgentPlugins/',
)
# WATCHDOG_TARGETS_EXCLUDE_END

# WATCHDOG_TARGETS_SIGNATURE_ALLOW
SIGNATURE_ALLOW = (
    'com.jamfsoftware.',
    'com.jamf.management.',
    'com.jamf.appinstallers.',
    'com.jamf.selfservice',
)
# WATCHDOG_TARGETS_SIGNATURE_ALLOW_END

# WATCHDOG_TARGETS_SIGNATURE_CONNECT
SIGNATURE_CONNECT = (
    'com.jamf.connect.',
    'com.jamf.connect',
)
# WATCHDOG_TARGETS_SIGNATURE_CONNECT_END

# WATCHDOG_TARGETS_SIGNATURE_DENY
SIGNATURE_DENY = (
    'com.jamf.protect',
    'com.jamf.complianceeditor',
    'com.txhaflaire',
)
# WATCHDOG_TARGETS_SIGNATURE_DENY_END

CORE_JOB_LABELS = {
    'com.jamf.management.daemon',
    'com.jamf.management.agent',
    'com.jamf.management.service',
    'com.jamf.management.login',
    'com.jamf.management.jamfAAD',
    'com.jamfsoftware.startupItem',
    'com.jamfsoftware.jamf.daemon',
}

WALK_ROOTS = (
    '/Library/Application Support/JAMF',
    '/Library/Application Support/JamfAppInstallers',
    '/Applications/Self Service.app',
    '/Applications/Jamf Self Service.app',
)

CONNECT_WALK_ROOTS = (
    '/Applications/Jamf Connect.app',
    '/Applications/Jamf Connect Configuration.app',
    '/Library/Application Support/JamfConnect',
)

CONNECT_WARNING = (
    'WARNING: Jamf Connect blocking is enabled. If this Mac uses Jamf Connect '
    'at the login window, users can be locked out until WatchDog is uninstalled. '
    'WatchDog never rewrites authorizationdb and never changes login-window '
    'SecurityAgentPlugins. Uninstall restores recorded execute bits and re-enables '
    'recorded launch jobs. Use a disposable test Mac with an alternative admin login.'
)


def excluded(path):
    text = str(path)
    for prefix in EXCLUDE_PREFIXES:
        base = prefix.rstrip('/')
        if text == base or text.startswith(prefix):
            return True
    return False


def job_label(label, block_connect=False):
    if not isinstance(label, str) or not label:
        return False
    if label.startswith('com.jamf.protect') or label.startswith('com.jamf.complianceeditor'):
        return False
    if label.startswith('com.jamfsoftware.task.'):
        return True
    if label in CORE_JOB_LABELS:
        return True
    if label.startswith('com.jamfsoftware.selfservice') or label.startswith('com.jamf.selfservice'):
        return True
    if label.startswith('com.jamf.appinstallers.'):
        return True
    if block_connect and (label == 'com.jamf.connect' or label.startswith('com.jamf.connect.')):
        return True
    return False


def signature_allowed(identifier, block_connect=False):
    if not identifier:
        return False
    for prefix in SIGNATURE_DENY:
        if identifier == prefix or identifier.startswith(prefix):
            return False
    for prefix in SIGNATURE_ALLOW:
        if identifier == prefix.rstrip('.') or identifier.startswith(prefix):
            return True
    if block_connect:
        for prefix in SIGNATURE_CONNECT:
            if identifier == prefix.rstrip('.') or identifier.startswith(prefix):
                return True
    return False


def _walk_root(root, found):
    path = Path(root)
    if excluded(path) or not path.exists():
        return
    if path.is_symlink():
        return
    if path.is_file():
        found.add(path)
        return
    for folder, dirs, files in os.walk(path, followlinks=False):
        dirs[:] = [name for name in dirs if not (Path(folder) / name).is_symlink()
                   and not excluded(Path(folder) / name)]
        for name in files:
            candidate = Path(folder) / name
            if candidate.is_symlink() or excluded(candidate):
                continue
            try:
                mode = candidate.stat().st_mode
            except OSError:
                continue
            if stat.S_ISREG(mode) and mode & 0o111:
                found.add(candidate)


def executables(block_connect=False, roots=None):
    """Return paths to inspect. Symlinks stay listed so callers can skip them with O_NOFOLLOW."""
    found = {Path(p) for p in EXACT_PATHS}
    search = list(roots) if roots is not None else list(WALK_ROOTS)
    if roots is None and block_connect:
        search.extend(CONNECT_WALK_ROOTS)
        found.update(Path(p) for p in CONNECT_EXACT_PATHS)
    for root in search:
        _walk_root(root, found)
    return sorted(path for path in found if not excluded(path))
