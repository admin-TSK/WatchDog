#!/usr/bin/env python3
"""Install, inspect, or remove WatchDog. Installation requires administrator access."""
import argparse
import datetime
import json
import os
from pathlib import Path
import plistlib
import shutil
import stat
import subprocess
import sys
import time

LABEL = 'local.watchdog.guard'
ROOT = Path('/Library/Application Support/WatchDog')
LAUNCHDAEMONS = Path('/Library/LaunchDaemons')
PLIST = LAUNCHDAEMONS / f'{LABEL}.plist'
AUDIT_DIR = Path('/var/log')
LOG = Path('/var/log/watchdog.log')
LEGACY_ROOT = Path('/Library/Application Support/Jamf Test Blocker')
REPO = Path(__file__).resolve().parents[1]


def run(*args, check=True):
    return subprocess.run(args, text=True, capture_output=True, check=check, timeout=30)


def service_loaded(label):
    return run('/bin/launchctl', 'print', f'system/{label}', check=False).returncode == 0


def installed():
    """Recognize current and legacy installs without embedding a site-specific label."""
    candidates = [PLIST, *sorted(LAUNCHDAEMONS.glob('*.jamf-test-blocker.plist'))]
    for path in candidates:
        if not path.exists():
            continue
        data = plistlib.loads(path.read_bytes())
        args = data.get('ProgramArguments', [])
        for root in (ROOT, LEGACY_ROOT):
            if str(root / 'guard.py') in args and args and Path(args[0]).is_absolute():
                return root, path, data['Label'], args[0]
    return None


def make_plist(python):
    return {
        'Label': LABEL,
        'ProgramArguments': [python, '-I', str(ROOT / 'guard.py')],
        'RunAtLoad': True,
        'KeepAlive': True,
        'ThrottleInterval': 10,
        'ExitTimeOut': 10,
        'ProcessType': 'Background',
        'Umask': 0o077,
        'StandardOutPath': str(LOG),
        'StandardErrorPath': str(LOG),
    }


def install():
    existing = installed()
    if existing or ROOT.exists() or ROOT.is_symlink() or LEGACY_ROOT.exists() or PLIST.exists() or PLIST.is_symlink():
        raise RuntimeError('WatchDog or its legacy version is already installed. Use Uninstall.command before a fresh install; no changes made.')
    binary = REPO / 'build' / 'watchdog'
    if not binary.is_file():
        raise RuntimeError('Build WatchDog first with scripts/build.sh.')
    run('/usr/bin/codesign', '--verify', '--strict', str(binary))
    python = str(Path(sys.executable).resolve())
    ROOT.mkdir(mode=0o700)
    try:
        for source, name, mode in [(binary, 'watchdog', 0o700), (REPO / 'src' / 'guard.py', 'guard.py', 0o600), (REPO / 'src' / 'processes.py', 'processes.py', 0o600)]:
            destination = ROOT / name
            shutil.copyfile(source, destination)
            destination.chmod(mode)
        (ROOT / 'installation.json').write_text(json.dumps({'label': LABEL, 'python': python, 'version': (REPO / 'VERSION').read_text().strip()}, indent=2))
        (ROOT / 'installation.json').chmod(0o600)
        PLIST.write_bytes(plistlib.dumps(make_plist(python)))
        PLIST.chmod(0o644)
        run('/usr/bin/plutil', '-lint', str(PLIST))
        first = run(python, '-I', str(ROOT / 'guard.py'), '--once')
        print(first.stdout, end='')
        run('/bin/launchctl', 'enable', f'system/{LABEL}')
        run('/bin/launchctl', 'bootstrap', 'system', str(PLIST))
        time.sleep(1)
        check = run('/bin/launchctl', 'print', f'system/{LABEL}').stdout
        if 'state = running' not in check:
            raise RuntimeError('WatchDog did not remain running.')
        state = json.loads((ROOT / 'state.json').read_text())
        for path in state['modes']:
            if Path(path).exists() and stat.S_IMODE(os.stat(path).st_mode) & 0o111:
                raise RuntimeError(f'Execution permission remains on {path}')
        print('WatchDog installed and running. MDM enrollment is unchanged.')
    except BaseException:
        run('/bin/launchctl', 'bootout', f'system/{LABEL}', check=False)
        if (ROOT / 'state.json').exists():
            restored = run(python, '-I', str(ROOT / 'guard.py'), '--restore', check=False)
            print(restored.stdout, end='')
            if restored.returncode:
                print('Some settings could not be restored. Retain the undo state and run Uninstall.command again.', file=sys.stderr)
        print('Installation stopped; recovery files were retained. Run Uninstall.command to finish cleanup.', file=sys.stderr)
        raise


def uninstall():
    existing = installed()
    if existing is None:
        # Recover a partially created fresh installation with no plist.
        config = ROOT / 'installation.json'
        if config.exists():
            data = json.loads(config.read_text())
            existing = (ROOT, PLIST, data['label'], data['python'])
        elif ROOT.exists() or LEGACY_ROOT.exists():
            raise RuntimeError('Installation data is incomplete. Retain the folder and recover from its undo record before removing files.')
        else:
            print('WatchDog is not installed.')
            return
    root, plist, label, python = existing
    if service_loaded(label):
        run('/bin/launchctl', 'bootout', f'system/{label}')
    if service_loaded(label):
        raise RuntimeError('WatchDog is still running; restoration stopped.')
    state = root / 'state.json'
    if state.exists():
        restored = run(python, '-I', str(root / 'guard.py'), '--restore')
        print(restored.stdout, end='')
        stamp = datetime.datetime.now().strftime('%Y%m%d-%H%M%S-%f')
        backup = AUDIT_DIR / f'watchdog-restored-{stamp}.json'
        shutil.copyfile(state, backup)
        backup.chmod(0o600)
        print(f'Undo record preserved: {backup}')
    plist.unlink(missing_ok=True)
    for name in ('watchdog', 'jamf-test-blocker', 'guard.py', 'processes.py', 'state.json', 'state.tmp', 'installation.json'):
        (root / name).unlink(missing_ok=True)
    root.rmdir()  # Refuse to discard unexpected files.
    print('WatchDog removed. Recorded settings restored; MDM enrollment unchanged.')


def status():
    existing = installed()
    if existing is None:
        print('WatchDog is not installed.')
        return
    root, plist, label, python = existing
    result = run('/bin/launchctl', 'print', f'system/{label}', check=False)
    print('WatchDog: ' + ('running' if 'state = running' in result.stdout else 'not running'))
    if root == LEGACY_ROOT:
        print('Installation: legacy service (compatible with this repository’s uninstall command).')
    print(f'Service: {label}')
    binary = Path('/usr/local/jamf/bin/jamf')
    print('Main Jamf binary: ' + ('absent' if not binary.exists() else 'execution blocked' if not stat.S_IMODE(binary.stat().st_mode) & 0o111 else 'executable'))
    print(f'Undo state: {root / "state.json"}')
    print('MDM enrollment is outside WatchDog’s scope.')


def main():
    parser = argparse.ArgumentParser(description='WatchDog lifecycle management')
    parser.add_argument('action', choices=('install', 'uninstall', 'status'))
    args = parser.parse_args()
    if sys.platform != 'darwin':
        parser.error('WatchDog supports macOS only.')
    if args.action != 'status' and os.geteuid() != 0:
        parser.error('Use Install.command or Uninstall.command to authenticate as an administrator.')
    if args.action != 'status':
        os.umask(0o077)
    try:
        globals()[args.action]()
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as e:
        print(f'WatchDog: {e}', file=sys.stderr)
        if isinstance(e, subprocess.CalledProcessError):
            print(e.stdout or '', end='', file=sys.stderr)
            print(e.stderr or '', end='', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
