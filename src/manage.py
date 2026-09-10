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
EVENTS_LABEL = 'local.watchdog.events'
ROOT = Path('/Library/Application Support/WatchDog')
LAUNCHDAEMONS = Path('/Library/LaunchDaemons')
PLIST = LAUNCHDAEMONS / f'{LABEL}.plist'
AUDIT_DIR = Path('/var/log')
LOG = Path('/var/log/watchdog.log')
LEGACY_ROOT = Path('/Library/Application Support/Jamf Test Blocker')
NEWSYSLOG = Path('/etc/newsyslog.d/local.watchdog.conf')
EVENTS_JSON = Path('/Library/Application Support/WatchDog Status/events.json')
APPLICATION = Path('/Applications/WatchDog.app')
REPO = Path(__file__).resolve().parents[1]


def run(*args, check=True):
    return subprocess.run(args, text=True, capture_output=True, check=check, timeout=30)


def env_flag(name):
    return os.environ.get(name, '').strip() in {'1', 'true', 'TRUE', 'yes', 'YES'}


def interpreter_volatile(path):
    text = str(path)
    return any(part in text for part in (
        '/opt/homebrew/', '/usr/local/Cellar/', '/Cellar/',
        'Python.framework/Versions/', '/.pyenv/', '/venv/', '/.venv/',
    ))


def python_fallbacks(primary):
    ordered = []
    for path in (primary, '/usr/bin/python3', '/usr/local/bin/python3'):
        if path and path not in ordered:
            ordered.append(path)
    return ordered


def write_runner(path, script_name, candidates):
    quoted = '\n'.join(f'  "{item}"' for item in candidates)
    path.write_text(f'''#!/bin/bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
CANDIDATES=(
{quoted}
)
for py in "${{CANDIDATES[@]}}"; do
  if [[ -x "$py" ]] && "$py" -I -c 'import sys; raise SystemExit(sys.version_info < (3, 10))' 2>/dev/null; then
    exec "$py" -I "$ROOT/{script_name}" "$@"
  fi
done
echo "WatchDog: no Python 3.10+ interpreter among: ${{CANDIDATES[*]}}" >&2
exit 1
''')
    path.chmod(0o700)


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
            if args and args[0] == str(root / 'run-guard'):
                python = '/usr/bin/python3'
                config = root / 'installation.json'
                if config.exists():
                    python = json.loads(config.read_text()).get('python', python)
                return root, path, data['Label'], python
    return None


def make_plist(python=None):
    return {
        'Label': LABEL,
        'ProgramArguments': [str(ROOT / 'run-guard')],
        'RunAtLoad': True,
        'KeepAlive': True,
        'ThrottleInterval': 10,
        'ExitTimeOut': 10,
        'ProcessType': 'Background',
        'Umask': 0o077,
        'StandardOutPath': str(LOG),
        'StandardErrorPath': str(LOG),
    }


def execute_state(path):
    target = Path(path)
    try:
        info = os.lstat(target)
    except FileNotFoundError:
        return 'absent'
    if stat.S_ISLNK(info.st_mode):
        return 'symlink'
    if info.st_mode & 0o111:
        return 'executable'
    return 'execution blocked'


def install():
    existing = installed()
    if existing or ROOT.exists() or ROOT.is_symlink() or LEGACY_ROOT.exists() or PLIST.exists() or PLIST.is_symlink():
        raise RuntimeError('WatchDog or its legacy version is already installed. Run ./uninstall.sh before a fresh install; no changes made.')
    binary = REPO / 'build' / 'watchdog'
    if not binary.is_file():
        raise RuntimeError('Build WatchDog first with scripts/build.sh.')
    run('/usr/bin/codesign', '--verify', '--strict', str(binary))
    python = str(Path(sys.executable).resolve())
    fallbacks = python_fallbacks(python)
    sticky = env_flag('WATCHDOG_STICKY_BLOCK')
    match_signature = env_flag('WATCHDOG_MATCH_SIGNATURE')
    block_connect = env_flag('WATCHDOG_BLOCK_CONNECT')
    if interpreter_volatile(python):
        print(f'WatchDog: warning: {python} looks like a removable runtime. Fallbacks: {", ".join(fallbacks)}', file=sys.stderr)
    if block_connect:
        spec = __import__('importlib.util').util.spec_from_file_location('watchdog_targets', REPO / 'src' / 'targets.py')
        module = __import__('importlib.util').util.module_from_spec(spec)
        spec.loader.exec_module(module)
        print(module.CONNECT_WARNING, file=sys.stderr)
    ROOT.mkdir(mode=0o700)
    try:
        for source, name, mode in [
            (binary, 'watchdog', 0o700),
            (REPO / 'src' / 'guard.py', 'guard.py', 0o600),
            (REPO / 'src' / 'processes.py', 'processes.py', 0o600),
            (REPO / 'src' / 'targets.py', 'targets.py', 0o600),
            (REPO / 'src' / 'shields.py', 'shields.py', 0o600),
        ]:
            destination = ROOT / name
            shutil.copyfile(source, destination)
            destination.chmod(mode)
        write_runner(ROOT / 'run-guard', 'guard.py', fallbacks)
        NEWSYSLOG.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(REPO / 'src' / 'newsyslog.conf', NEWSYSLOG)
        NEWSYSLOG.chmod(0o644)
        installation = {
            'label': LABEL,
            'python': python,
            'python_fallbacks': fallbacks,
            'version': (REPO / 'VERSION').read_text().strip(),
            'permission_interval': 0.1,
            'background_interval': 2.0,
            'monitor_interval_ms': 50,
            'sticky_block': sticky,
            'match_signature': match_signature,
            'block_connect': block_connect,
        }
        (ROOT / 'installation.json').write_text(json.dumps(installation, indent=2))
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
            if Path(path).exists() and not Path(path).is_symlink() and stat.S_IMODE(os.stat(path).st_mode) & 0o111:
                raise RuntimeError(f'Execution permission remains on {path}')
        print('WatchDog installed and running. MDM enrollment is unchanged.')
        print('Defaults: permission 100 ms, monitor 50 ms. Optional flags: WATCHDOG_STICKY_BLOCK, WATCHDOG_MATCH_SIGNATURE, WATCHDOG_BLOCK_CONNECT.')
    except BaseException:
        run('/bin/launchctl', 'bootout', f'system/{LABEL}', check=False)
        if (ROOT / 'state.json').exists():
            restored = run(python, '-I', str(ROOT / 'guard.py'), '--restore', check=False)
            print(restored.stdout, end='')
            if restored.returncode:
                print('Some settings could not be restored. Retain the undo state and run ./uninstall.sh again.', file=sys.stderr)
        print('Installation stopped; recovery files were retained. Run ./uninstall.sh to finish cleanup.', file=sys.stderr)
        raise


def uninstall():
    existing = installed()
    if existing is None:
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
        run('/bin/launchctl', 'bootout', f'system/{label}', check=False)
        deadline = time.time() + 15
        while service_loaded(label) and time.time() < deadline:
            run('/bin/launchctl', 'bootout', f'system/{label}', check=False)
            time.sleep(0.25)
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
    NEWSYSLOG.unlink(missing_ok=True)
    for name in ('watchdog', 'jamf-test-blocker', 'guard.py', 'processes.py', 'targets.py', 'shields.py',
                 'run-guard', 'state.json', 'state.tmp', 'installation.json', 'shields.json'):
        (root / name).unlink(missing_ok=True)
    root.rmdir()
    print('WatchDog removed. Recorded settings restored; MDM enrollment unchanged.')


def status():
    existing = installed()
    if existing is None:
        print('WatchDog is not installed.')
        return
    root, plist, label, python = existing
    result = run('/bin/launchctl', 'print', f'system/{label}', check=False)
    running = 'state = running' in result.stdout
    print('WatchDog: ' + ('running' if running else 'not running'))
    if root == LEGACY_ROOT:
        print('Installation: legacy service (compatible with this repository’s ./uninstall.sh).')
    print(f'Service: {label}')
    print(f'Python: {python}')
    pid_match = __import__('re').search(r'^\s*pid = (\d+)', result.stdout, __import__('re').MULTILINE)
    monitor_paths = [str(root / 'watchdog'), str(root / 'jamf-test-blocker')]
    monitor = False
    if pid_match:
        spec = __import__('importlib.util').util.spec_from_file_location('watchdog_processes', Path(__file__).with_name('processes.py'))
        processes = __import__('importlib.util').util.module_from_spec(spec)
        spec.loader.exec_module(processes)
        try:
            monitor = processes.has_child(int(pid_match[1]), monitor_paths)
        except OSError:
            monitor = False
    print('Process monitor: ' + ('running' if monitor else 'not running'))
    events = run('/bin/launchctl', 'print', f'system/{EVENTS_LABEL}', check=False)
    print('Event reader: ' + ('running' if 'state = running' in events.stdout else 'not running'))
    app = APPLICATION / 'Contents/MacOS/WatchDog'
    print('Menu bar app: ' + ('installed' if app.exists() else 'not installed'))
    if (root / 'installation.json').exists():
        info = json.loads((root / 'installation.json').read_text())
        print(f'Version: {info.get("version", "unknown")}')
        print(f'Sticky block: {info.get("sticky_block", False)}')
        print(f'Signature matching: {info.get("match_signature", False)}')
        print(f'Jamf Connect blocking: {info.get("block_connect", False)}')
    shields_path = root / 'shields.json'
    if shields_path.exists():
        try:
            live = json.loads(shields_path.read_text())
            print('Shields: ' + ', '.join(
                f'{key}={"on" if live.get(key) else "off"}'
                for key in ('permissions', 'jobs', 'monitor', 'sticky', 'signatures', 'connect')))
        except (OSError, ValueError, TypeError):
            print('Shields: unreadable')
    state_path = root / 'state.json'
    if state_path.exists():
        state = json.loads(state_path.read_text())
        modes = state.get('modes', {})
        print(f'Tracked executables: {len(modes)}')
        for path in sorted(modes):
            print(f'  {path}: {execute_state(path)}')
        print(f'Recorded jobs: {len(state.get("jobs", {}))}')
    else:
        print(f'Main Jamf binary: {execute_state("/usr/local/jamf/bin/jamf")}')
    if EVENTS_JSON.exists():
        try:
            snapshot = json.loads(EVENTS_JSON.read_text())
            age = time.time() - float(snapshot.get('updated_at', 0))
            print(f'Activity snapshot age: {age:.1f}s')
        except (OSError, ValueError, TypeError):
            print('Activity snapshot: unreadable')
    else:
        print('Activity snapshot: absent')
    print(f'Undo state: {state_path}')
    print('MDM enrollment is outside WatchDog’s scope.')


def main():
    parser = argparse.ArgumentParser(description='WatchDog lifecycle management')
    parser.add_argument('action', choices=('install', 'uninstall', 'status'))
    args = parser.parse_args()
    if sys.platform != 'darwin':
        parser.error('WatchDog supports macOS only.')
    if args.action != 'status' and os.geteuid() != 0:
        parser.error('Run ./install.sh or ./uninstall.sh to authenticate as an administrator.')
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
