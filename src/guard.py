#!/usr/bin/env python3
"""WatchDog: reversible Jamf Pro framework controls; does not alter MDM enrollment."""
import json, os, plistlib, re, signal, stat, subprocess, sys, threading, time
from pathlib import Path

ROOT = Path(__file__).resolve().parent
STATE = ROOT / 'state.json'
APP = Path('/Library/Application Support/JAMF/Jamf.app')
PERMISSION_INTERVAL = 0.2
BACKGROUND_INTERVAL = 2.0
STATE_LOCK = threading.RLock()
BASE_EXECUTABLES = {Path('/usr/local/jamf/bin/jamf'), Path('/usr/local/jamf/bin/jamfAgent')}

def log(message):
    print(time.strftime('%Y-%m-%d %H:%M:%S'), message, flush=True)

def load_state():
    if STATE.exists():
        return json.loads(STATE.read_text())
    return {'version': 1, 'modes': {}, 'jobs': {}}

def save_state(state):
    # Both loops journal before changing controls. Never hold this lock across
    # a subprocess or filesystem discovery scan.
    with STATE_LOCK:
        tmp = STATE.with_suffix('.tmp')
        with open(tmp, 'w') as f:
            os.chmod(tmp, 0o600)
            json.dump(state, f, indent=2)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, STATE)


def command(*args):
    return subprocess.run(args, text=True, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, timeout=10)

def executables():
    paths = set(BASE_EXECUTABLES)
    if APP.exists():
        for folder, dirs, files in os.walk(APP, followlinks=False):
            dirs[:] = [d for d in dirs if not (Path(folder) / d).is_symlink()]
            if 'Info.plist' not in files or Path(folder).name != 'Contents':
                continue
            try:
                with open(Path(folder) / 'Info.plist', 'rb') as f:
                    executable = plistlib.load(f).get('CFBundleExecutable', '')
                if executable and '/' not in executable and executable not in ('.', '..'):
                    paths.add(Path(folder) / 'MacOS' / executable)
            except (OSError, ValueError, plistlib.InvalidFileException) as e:
                log(f'Cannot inspect {folder}: {e}')
    return sorted(paths)

def block_modes(state, paths):
    failures = []
    for path in paths:
        try:
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        except FileNotFoundError:
            continue
        except OSError as e:
            failures.append(f'{path}: {e}')
            continue
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode):
                raise RuntimeError('Target is not a regular file')
            mode = stat.S_IMODE(info.st_mode)
            if mode & 0o111:
                key = str(path)
                with STATE_LOCK:
                    if key not in state['modes']:
                        state['modes'][key] = mode
                        save_state(state)  # Durable undo record before mutation.
                os.fchmod(fd, mode & ~0o111)
                if stat.S_IMODE(os.fstat(fd).st_mode) & 0o111:
                    raise RuntimeError('Execution permission was not removed')
                log(f'Execution blocked: {path}')
        except Exception as e:
            failures.append(f'{path}: {e}')
        finally:
            os.close(fd)
    return failures

def job_label(label):
    return (label.startswith('com.jamfsoftware.task.') or
            label in {'com.jamf.management.daemon', 'com.jamf.management.agent',
                      'com.jamf.management.service', 'com.jamf.management.login',
                      'com.jamfsoftware.startupItem', 'com.jamfsoftware.jamf.daemon'})

def jobs():
    result = {('system', 'com.jamfsoftware.task.1'): (None, False),
              ('system', 'com.jamf.management.daemon'): (None, False)}
    uids = {os.stat('/dev/console').st_uid}
    # Active GUI sessions, including fast user switching.
    ps = command('/bin/ps', '-axo', 'uid=,comm=')
    for line in ps.stdout.splitlines():
        fields = line.strip().split(None, 1)
        if len(fields) == 2 and fields[1].endswith('/loginwindow'):
            uids.add(int(fields[0]))
    scans = [(Path('/Library/LaunchDaemons'), ['system']),
             (Path('/Library/LaunchAgents'), [f'gui/{u}' for u in uids if u >= 500])]
    for folder, domains in scans:
        for path in folder.glob('*.plist'):
            if path.is_symlink():
                continue
            try:
                with open(path, 'rb') as f:
                    data = plistlib.load(f)
            except (OSError, ValueError, plistlib.InvalidFileException):
                continue
            label = data.get('Label', '')
            if isinstance(label, str) and job_label(label):
                for domain in domains:
                    result[(domain, label)] = (str(path), bool(data.get('Disabled', False)))
    return result

def block_jobs(state):
    failures, overrides = [], {}
    for (domain, label), (path, default_disabled) in jobs().items():
        if domain not in overrides:
            status = command('/bin/launchctl', 'print-disabled', domain)
            if status.returncode:
                overrides[domain] = None
            else:
                overrides[domain] = dict(re.findall(r'"([^"\n]+)"\s*=>\s*(true|false|disabled|enabled)', status.stdout))
        if overrides[domain] is None:
            if domain == 'system': failures.append('Cannot read launchd system state')
            continue
        key = f'{domain}/{label}'
        is_loaded = command('/bin/launchctl', 'print', key).returncode == 0
        with STATE_LOCK:
            if key not in state['jobs']:
                original = overrides[domain].get(label)
                state['jobs'][key] = {'disabled': original in ('true', 'disabled') if original is not None else default_disabled,
                                      'loaded': is_loaded, 'path': path}
                save_state(state)
        if overrides[domain].get(label) not in ('true', 'disabled'):
            action = command('/bin/launchctl', 'disable', key)
            if action.returncode:
                failures.append(f'Could not disable {key}: {action.stderr.strip()}')
                continue
            log(f'Launch job disabled: {key}')
        if is_loaded:
            action = command('/bin/launchctl', 'bootout', key)
            if action.returncode and command('/bin/launchctl', 'print', key).returncode == 0:
                failures.append(f'Could not unload {key}: {action.stderr.strip()}')
            else:
                log(f'Launch job unloaded: {key}')
    return failures

def restore_modes(state):
    failures = []
    for path, mode in state['modes'].items():
        try:
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
            try:
                os.fchmod(fd, mode)
                log(f'Original permissions restored: {path}')
            finally:
                os.close(fd)
        except FileNotFoundError:
            log(f'Restore skipped; file no longer exists: {path}')
        except OSError as e:
            failures.append(f'{path}: {e}')
    return failures

def restore(state):
    failures = restore_modes(state)
    for key, original in state['jobs'].items():
        if original.get('original_override_unverified'):
            log(f'NOTE: {key} pre-install override was not captured; restoring the documented enabled default.')
        action = command('/bin/launchctl', 'disable' if original['disabled'] else 'enable', key)
        if action.returncode:
            failures.append(f'Could not restore {key}: {action.stderr.strip()}')
            continue
        path = original['path']
        if original['loaded'] and path and Path(path).exists():
            if command('/bin/launchctl', 'print', key).returncode != 0:
                domain = key.rsplit('/', 1)[0]
                action = command('/bin/launchctl', 'bootstrap', domain, path)
                if action.returncode:
                    failures.append(f'Could not reload {key}: {action.stderr.strip()}')
                    continue
        log(f'Original launch-job state restored: {key}')
    return failures

class BackgroundChecks(threading.Thread):
    """Slow discovery and launchctl work cannot hold up permission polling."""
    def __init__(self, state, stop_event, initial_paths=None):
        super().__init__(name='watchdog-background-checks', daemon=True)
        self.state = state
        self.stop_event = stop_event
        self.path_lock = threading.Lock()
        self.cached_paths = sorted(initial_paths if initial_paths is not None else
                                   BASE_EXECUTABLES | {Path(p) for p in state['modes']})

    def paths(self):
        with self.path_lock:
            return list(self.cached_paths)

    def run(self):
        while not self.stop_event.is_set():
            started = time.monotonic()
            try:
                discovered = executables()
                with STATE_LOCK:
                    tracked = {Path(p) for p in self.state['modes']}
                with self.path_lock:
                    self.cached_paths = sorted(set(discovered) | tracked)
                for failure in block_jobs(self.state):
                    log('PROTECTION ERROR: ' + failure)
            except subprocess.TimeoutExpired as error:
                log('PROTECTION ERROR: Background status check timed out; permission checks continue independently. ' + repr(error))
            except Exception as error:
                log('PROTECTION ERROR: Background check: ' + repr(error))
            self.stop_event.wait(max(0, BACKGROUND_INTERVAL - (time.monotonic() - started)))


def run_permission_checks(state, background, stop_event, supervise=lambda: None):
    while not stop_event.is_set():
        started = time.monotonic()
        supervise()
        try:
            for failure in block_modes(state, background.paths()):
                log('PROTECTION ERROR: ' + failure)
        except Exception as error:
            log('PROTECTION ERROR: Permission check: ' + repr(error))
        # Account for work time instead of adding a fixed sleep after each pass.
        stop_event.wait(max(0, PERMISSION_INTERVAL - (time.monotonic() - started)))


def main():
    if os.geteuid() != 0:
        sys.exit('Administrator authentication is required.')
    os.umask(0o077)
    state = load_state()
    if '--restore' in sys.argv:
        failures = restore(state)
        for failure in failures: log('RESTORE ERROR: ' + failure)
        return bool(failures)
    stop_event = threading.Event()
    def stop(signum, frame):
        stop_event.set()
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    watcher = None
    background = None
    def supervise():
        nonlocal watcher
        if watcher is None or watcher.poll() is not None:
            executable = ROOT / 'watchdog'
            if not executable.exists():
                executable = ROOT / 'jamf-test-blocker'  # Legacy installation.
            watcher = subprocess.Popen([str(executable)])
            log('WatchDog process monitor started.')
    try:
        supervise()
        if '--once' in sys.argv:
            failures = block_modes(state, executables()) + block_jobs(state)
            for failure in failures: log('PROTECTION ERROR: ' + failure)
            return bool(failures)
        background = BackgroundChecks(state, stop_event)
        background.start()
        log('Permission checks: 200 ms; background discovery/job checks: 2 seconds; process monitor: 100 ms.')
        run_permission_checks(state, background, stop_event, supervise)
    finally:
        stop_event.set()
        if background:
            background.join(timeout=0.5)
        if watcher and watcher.poll() is None:
            watcher.terminate()
            try: watcher.wait(timeout=3)
            except subprocess.TimeoutExpired:
                watcher.kill()
                watcher.wait()
    return 0

if __name__ == '__main__':
    sys.exit(main())
