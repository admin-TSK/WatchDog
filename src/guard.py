#!/usr/bin/env python3
"""WatchDog: reversible Jamf local-component controls; does not alter MDM enrollment."""
import json, os, plistlib, re, signal, stat, subprocess, sys, threading, time
from pathlib import Path

import importlib.util
sys.dont_write_bytecode = True

def _load(name):
    spec = importlib.util.spec_from_file_location(f'watchdog_{name}', Path(__file__).with_name(f'{name}.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

processes = _load('processes')
targets = _load('targets')
shields = _load('shields')

ROOT = Path(__file__).resolve().parent
STATE = ROOT / 'state.json'
CONFIG_PATH = ROOT / 'installation.json'
PERMISSION_INTERVAL = 0.1
BACKGROUND_INTERVAL = 2.0
MONITOR_INTERVAL_MS = 50
STATE_VERSION = 2
UF_IMMUTABLE = getattr(stat, 'UF_IMMUTABLE', 0x00000002)
STATE_LOCK = threading.RLock()
BASE_EXECUTABLES = {Path(p) for p in targets.EXACT_PATHS}
SESSION_LOOKUP_HEALTHY = False
SHIELDS = dict(shields.DEFAULTS)
SHIELDS_READY = False
CONFIG = {
    'permission_interval': PERMISSION_INTERVAL,
    'background_interval': BACKGROUND_INTERVAL,
    'monitor_interval_ms': MONITOR_INTERVAL_MS,
    'sticky_block': False,
    'match_signature': False,
    'block_connect': False,
}

def log(message):
    print(time.strftime('%Y-%m-%d %H:%M:%S'), message, flush=True)

def load_config():
    config = dict(CONFIG)
    if not CONFIG_PATH.exists():
        return config
    try:
        data = json.loads(CONFIG_PATH.read_text())
    except (OSError, ValueError):
        return config
    for key, cast in (('permission_interval', float), ('background_interval', float),
                      ('monitor_interval_ms', int), ('sticky_block', bool),
                      ('match_signature', bool), ('block_connect', bool)):
        if key in data:
            try:
                config[key] = cast(data[key])
            except (TypeError, ValueError):
                pass
    if config['permission_interval'] < 0.05:
        config['permission_interval'] = 0.05
    if config['background_interval'] < 0.5:
        config['background_interval'] = 0.5
    config['monitor_interval_ms'] = max(1, min(2000, int(config['monitor_interval_ms'])))
    return config

def apply_config(config):
    global PERMISSION_INTERVAL, BACKGROUND_INTERVAL, MONITOR_INTERVAL_MS, CONFIG
    CONFIG = config
    PERMISSION_INTERVAL = config['permission_interval']
    BACKGROUND_INTERVAL = config['background_interval']
    MONITOR_INTERVAL_MS = config['monitor_interval_ms']


def refresh_shields():
    """Reload shields.json and mirror optional flags into CONFIG. Returns (current, previous)."""
    global SHIELDS, CONFIG, SHIELDS_READY
    with STATE_LOCK:
        previous = dict(SHIELDS)
        path = STATE.with_name('shields.json')
        current = shields.load(path, CONFIG)
        if not path.exists():
            shields.save(path, current)
        CONFIG['sticky_block'] = current['sticky']
        CONFIG['match_signature'] = current['signatures']
        CONFIG['block_connect'] = current['connect']
        if SHIELDS_READY:
            for key in shields.KEYS:
                if previous.get(key) != current[key]:
                    log(f'Shield {key} {"on" if current[key] else "off"}.')
                    if key == 'connect' and current[key]:
                        log(targets.CONNECT_WARNING)
        else:
            SHIELDS_READY = True
        SHIELDS = current
        return current, previous

def load_state():
    if STATE.exists():
        try:
            state = json.loads(STATE.read_text())
        except (OSError, ValueError):
            state = {}
    else:
        state = {}
    if not isinstance(state, dict):
        state = {}
    state.setdefault('modes', {})
    state.setdefault('jobs', {})
    state.setdefault('flags', {})
    if not isinstance(state['flags'], dict):
        state['flags'] = {}
    state['version'] = STATE_VERSION
    return state

def save_state(state):
    # Both loops journal before changing controls. Never hold this lock across
    # a subprocess or filesystem discovery scan.
    with STATE_LOCK:
        state['version'] = STATE_VERSION
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
    return targets.executables(block_connect=CONFIG['block_connect'])

def _file_flags(info):
    return int(getattr(info, 'st_flags', 0))

def _set_flags(path, flags):
    setter = getattr(os, 'lchflags', None) or os.chflags
    setter(path, flags)

def block_modes(state, paths, sticky=None):
    if sticky is None:
        sticky = CONFIG['sticky_block']
    failures = []
    for path in paths:
        try:
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        except FileNotFoundError:
            continue
        except OSError as e:
            if e.errno == 62:  # ELOOP: symlink; the real file is listed separately.
                continue
            failures.append(f'{path}: {e}')
            continue
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode):
                raise RuntimeError('Target is not a regular file')
            mode = stat.S_IMODE(info.st_mode)
            flags = _file_flags(info)
            key = str(path)
            mutated = False
            if mode & 0o111:
                with STATE_LOCK:
                    if key not in state['modes']:
                        state['modes'][key] = mode
                    if sticky and key not in state['flags']:
                        state['flags'][key] = flags
                    save_state(state)
                if flags & UF_IMMUTABLE:
                    _set_flags(path, flags & ~UF_IMMUTABLE)
                os.fchmod(fd, mode & ~0o111)
                if stat.S_IMODE(os.fstat(fd).st_mode) & 0o111:
                    raise RuntimeError('Execution permission was not removed')
                log(f'Execution blocked: {path}')
                mutated = True
                flags = _file_flags(os.fstat(fd))
            if sticky:
                with STATE_LOCK:
                    if key not in state['flags']:
                        state['flags'][key] = flags & ~UF_IMMUTABLE if mutated else flags
                        if key not in state['modes']:
                            state['modes'][key] = mode & ~0o111
                        save_state(state)
                current = _file_flags(os.fstat(fd))
                if current & UF_IMMUTABLE == 0:
                    _set_flags(path, current | UF_IMMUTABLE)
                    log(f'Sticky block applied: {path}')
        except Exception as e:
            failures.append(f'{path}: {e}')
        finally:
            os.close(fd)
    return failures

def job_label(label):
    return targets.job_label(label, block_connect=CONFIG['block_connect'])

def jobs():
    global SESSION_LOOKUP_HEALTHY
    result = {('system', 'com.jamfsoftware.task.1'): (None, False),
              ('system', 'com.jamf.management.daemon'): (None, False)}
    try:
        uids = processes.login_uids()
    except Exception:
        SESSION_LOOKUP_HEALTHY = False
        raise
    if not SESSION_LOOKUP_HEALTHY:
        log('Session discovery healthy: native process lookup.')
        SESSION_LOOKUP_HEALTHY = True
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
    flags_map = state.get('flags') or {}
    for path, mode in state['modes'].items():
        try:
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
            try:
                if path in flags_map:
                    _set_flags(path, int(flags_map[path]))
                    log(f'Original flags restored: {path}')
                os.fchmod(fd, mode)
                log(f'Original permissions restored: {path}')
            finally:
                os.close(fd)
        except FileNotFoundError:
            log(f'Restore skipped; file no longer exists: {path}')
        except OSError as e:
            failures.append(f'{path}: {e}')
    return failures

def restore_jobs(state):
    failures = []
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


def restore(state):
    return restore_modes(state) + restore_jobs(state)


def clear_sticky(state):
    failures = []
    for path in state.get('modes', {}):
        try:
            flags = int((state.get('flags') or {}).get(path, 0))
            _set_flags(Path(path), flags & ~UF_IMMUTABLE)
        except FileNotFoundError:
            continue
        except OSError as error:
            failures.append(f'{path}: {error}')
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
                current, previous = refresh_shields()
                if previous.get('jobs') and not current['jobs']:
                    for failure in restore_jobs(self.state):
                        log('PROTECTION ERROR: ' + failure)
                elif current['jobs']:
                    for failure in block_jobs(self.state):
                        log('PROTECTION ERROR: ' + failure)
                if previous.get('sticky') and not current['sticky']:
                    for failure in clear_sticky(self.state):
                        log('PROTECTION ERROR: ' + failure)
            except subprocess.TimeoutExpired as error:
                log('PROTECTION ERROR: Background status check timed out; permission checks continue independently. ' + repr(error))
            except Exception as error:
                log('PROTECTION ERROR: Background check: ' + repr(error))
            self.stop_event.wait(max(0, BACKGROUND_INTERVAL - (time.monotonic() - started)))


def run_permission_checks(state, background, stop_event, supervise=lambda: None):
    while not stop_event.is_set():
        started = time.monotonic()
        current, previous = refresh_shields()
        if previous.get('permissions') and not current['permissions']:
            for failure in restore_modes(state):
                log('PROTECTION ERROR: ' + failure)
        supervise()
        try:
            if current['permissions']:
                for failure in block_modes(state, background.paths()):
                    log('PROTECTION ERROR: ' + failure)
        except Exception as error:
            log('PROTECTION ERROR: Permission check: ' + repr(error))
        stop_event.wait(max(0, PERMISSION_INTERVAL - (time.monotonic() - started)))


def monitor_command():
    executable = ROOT / 'watchdog'
    if not executable.exists():
        executable = ROOT / 'jamf-test-blocker'
    if not executable.exists():
        return None, []
    args = [str(executable), '--interval-ms', str(int(MONITOR_INTERVAL_MS))]
    if CONFIG['match_signature']:
        args.append('--match-signature')
    if CONFIG['block_connect']:
        args.append('--block-connect')
    return executable, args


def main():
    if os.geteuid() != 0:
        sys.exit('Administrator authentication is required.')
    os.umask(0o077)
    apply_config(load_config())
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
    last_spawn = 0.0
    backoff = 1.0
    last_args = None
    def supervise():
        nonlocal watcher, last_spawn, backoff, last_args
        current, _previous = refresh_shields()
        if not current['monitor']:
            if watcher is not None and watcher.poll() is None:
                watcher.terminate()
                try:
                    watcher.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    watcher.kill()
                    watcher.wait()
                log('WatchDog process monitor stopped.')
            watcher = None
            last_args = None
            return
        executable, args = monitor_command()
        running = watcher is not None and watcher.poll() is None
        if running and last_args == args:
            return
        if running:
            watcher.terminate()
            try:
                watcher.wait(timeout=3)
            except subprocess.TimeoutExpired:
                watcher.kill()
                watcher.wait()
            watcher = None
        now = time.monotonic()
        if now < last_spawn + backoff:
            return
        last_spawn = now
        if executable is None:
            log('PROTECTION ERROR: Process monitor binary is missing; retrying.')
            backoff = min(backoff * 2, 30)
            return
        try:
            watcher = subprocess.Popen(args)
            last_args = args
            log('WatchDog process monitor started.')
            backoff = 1.0
        except OSError as error:
            log(f'PROTECTION ERROR: Could not start process monitor: {error}')
            backoff = min(backoff * 2, 30)
    try:
        refresh_shields()
        if CONFIG['block_connect']:
            log(targets.CONNECT_WARNING)
        supervise()
        if '--once' in sys.argv:
            failures = []
            if SHIELDS['permissions']:
                failures.extend(block_modes(state, executables()))
            if SHIELDS['jobs']:
                failures.extend(block_jobs(state))
            for failure in failures: log('PROTECTION ERROR: ' + failure)
            return bool(failures)
        background = BackgroundChecks(state, stop_event)
        background.start()
        log(f'Permission checks: {int(PERMISSION_INTERVAL * 1000)} ms; background discovery/job checks: {BACKGROUND_INTERVAL:g} seconds; process monitor: {MONITOR_INTERVAL_MS} ms.')
        run_permission_checks(state, background, stop_event, supervise)
    except Exception as error:
        log('PROTECTION ERROR: Guard failed: ' + repr(error))
        time.sleep(min(backoff, 5))
        return 1
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
