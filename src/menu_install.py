#!/usr/bin/env python3
"""Install the menu bar companion without changing the active guard."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import plistlib
import shutil
import signal
import subprocess
import sys
import time
import uuid

REPO = Path(__file__).resolve().parents[1]
PRIVATE = Path('/Library/Application Support/WatchDog Monitor')
PUBLIC = Path('/Library/Application Support/WatchDog Status')
LABEL = 'local.watchdog.events'
PLIST = Path('/Library/LaunchDaemons') / f'{LABEL}.plist'
APPLICATION = Path('/Applications/WatchDog.app')
BUNDLE_ID = 'local.watchdog.menubar'


def command(*args, check=True):
    return subprocess.run(args, check=check, capture_output=True, text=True, timeout=30)


def known_app(path):
    try:
        return plistlib.loads((path / 'Contents/Info.plist').read_bytes()).get('CFBundleIdentifier') == BUNDLE_ID
    except (OSError, ValueError):
        return False


def install():
    spec = importlib.util.spec_from_file_location('manage', REPO / 'src/manage.py')
    manage = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(manage)
    current = manage.installed()
    if not current:
        raise RuntimeError('Install the WatchDog guard first. No active installation was found.')
    root, guard_plist, guard_label, _ = current
    source = REPO / 'build/WatchDog.app'
    if not known_app(source):
        raise RuntimeError('Build the menu bar app first with scripts/build-menubar.sh.')
    if APPLICATION.exists() and not known_app(APPLICATION):
        raise RuntimeError('A different application already exists at /Applications/WatchDog.app.')
    for path in (PRIVATE, PUBLIC):
        if path.is_symlink():
            raise RuntimeError(f'Refusing a symbolic-link installation folder: {path}')
        if path.exists() and (path.stat().st_uid != 0 or path.stat().st_mode & 0o022):
            raise RuntimeError(f'Installation folder must be owned by root and not writable by other users: {path}')
    command('/usr/bin/codesign', '--verify', '--strict', str(source))
    guard_info = plistlib.loads(guard_plist.read_bytes())
    config = {'guard_label': guard_label, 'guard_root': str(root),
              'log_path': guard_info.get('StandardErrorPath', '/var/log/watchdog.log'),
              'monitor_paths': [str(root / 'watchdog'), str(root / 'jamf-test-blocker')]}
    PRIVATE.mkdir(mode=0o700, exist_ok=True)
    PUBLIC.mkdir(mode=0o755, exist_ok=True)
    PUBLIC.chmod(0o755)
    # Only the event reader is stopped during an update. The guard keeps running.
    command('/bin/launchctl', 'bootout', f'system/{LABEL}', check=False)
    shutil.copyfile(REPO / 'src/event_bridge.py', PRIVATE / 'event_bridge.py')
    (PRIVATE / 'event_bridge.py').chmod(0o600)
    (PRIVATE / 'config.json').write_text(json.dumps(config))
    (PRIVATE / 'config.json').chmod(0o600)
    data = {'Label': LABEL, 'ProgramArguments': [str(Path(sys.executable).resolve()), '-I', str(PRIVATE / 'event_bridge.py')],
            'RunAtLoad': True, 'KeepAlive': True, 'ThrottleInterval': 10, 'ExitTimeOut': 5,
            'ProcessType': 'Background', 'Umask': 0o077,
            'StandardOutPath': '/var/log/watchdog-events.log', 'StandardErrorPath': '/var/log/watchdog-events.log'}
    PLIST.write_bytes(plistlib.dumps(data))
    PLIST.chmod(0o644)
    temporary = APPLICATION.with_name(f'.WatchDog-{uuid.uuid4().hex}.app')
    shutil.copytree(source, temporary)
    # umask restricts new files; restore ordinary read/execute access to the app.
    for folder, dirs, files in os.walk(temporary):
        Path(folder).chmod(0o755)
        for name in files:
            path = Path(folder) / name
            path.chmod(0o755 if path.name == 'WatchDog' and path.parent.name == 'MacOS' else 0o644)
    command('/usr/bin/codesign', '--verify', '--strict', str(temporary))
    stop_app()
    if APPLICATION.exists(): shutil.rmtree(APPLICATION)
    temporary.rename(APPLICATION)
    command('/bin/launchctl', 'enable', f'system/{LABEL}')
    # launchd can briefly reject bootstrap while the old job is still being removed.
    for attempt in range(5):
        loaded = command('/bin/launchctl', 'bootstrap', 'system', str(PLIST), check=False)
        if loaded.returncode == 0:
            break
        if attempt == 4:
            raise RuntimeError('Could not start the activity reader: ' + loaded.stderr.strip())
        time.sleep(1)
    print('WatchDog menu bar companion installed. The existing guard was not restarted or changed.')


def login(enable):
    path = Path.home() / 'Library/LaunchAgents/local.watchdog.menubar.plist'
    if enable:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(plistlib.dumps({'Label': BUNDLE_ID, 'ProgramArguments': [str(APPLICATION / 'Contents/MacOS/WatchDog')], 'RunAtLoad': True}))
        path.chmod(0o644)
        command('/usr/bin/open', str(APPLICATION))
        print('WatchDog opened and configured to start at login for this user.')
    else:
        path.unlink(missing_ok=True)


def stop_app():
    processes = command('/bin/ps', '-axo', 'pid=,comm=').stdout
    for line in processes.splitlines():
        values = line.strip().split(None, 1)
        if len(values) == 2 and values[1] == str(APPLICATION / 'Contents/MacOS/WatchDog'):
            try: os.kill(int(values[0]), signal.SIGTERM)
            except ProcessLookupError: pass


def remove():
    command('/bin/launchctl', 'bootout', f'system/{LABEL}', check=False)
    if command('/bin/launchctl', 'print', f'system/{LABEL}', check=False).returncode == 0:
        raise RuntimeError('The event reader is still running; removal stopped.')
    stop_app()
    if APPLICATION.exists():
        if not known_app(APPLICATION): raise RuntimeError('Refusing to remove a different WatchDog application.')
        shutil.rmtree(APPLICATION)
    PLIST.unlink(missing_ok=True)
    for name in ('event_bridge.py', 'config.json', 'feed-state.json', 'feed-state.tmp'):
        (PRIVATE / name).unlink(missing_ok=True)
    if PRIVATE.exists(): PRIVATE.rmdir()
    for name in ('events.json', 'events.tmp'): (PUBLIC / name).unlink(missing_ok=True)
    if PUBLIC.exists(): PUBLIC.rmdir()
    print('Menu bar companion removed. The guard was not changed.')


def main():
    parser = argparse.ArgumentParser(description='WatchDog menu bar companion')
    parser.add_argument('action', choices=('install', 'remove', 'enable-login', 'disable-login'))
    args = parser.parse_args()
    if args.action in ('install', 'remove') and os.geteuid() != 0:
        parser.error('Administrator authentication is required.')
    if args.action.endswith('login') and os.geteuid() == 0:
        parser.error('Login configuration must run as the signed-in user, not root.')
    if args.action in ('install', 'remove'): os.umask(0o077)
    try:
        if args.action == 'install': install()
        elif args.action == 'remove': remove()
        else: login(args.action == 'enable-login')
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        print(f'WatchDog: {error}', file=sys.stderr)
        if isinstance(error, subprocess.CalledProcessError): print(error.stderr, file=sys.stderr)
        return 1
    return 0

if __name__ == '__main__': sys.exit(main())
