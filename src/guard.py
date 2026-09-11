#!/usr/bin/env python3
"""WatchDog: reversible Jamf local-component controls; does not alter MDM enrollment."""
import json, os, plistlib, pwd, re, signal, stat, subprocess, sys, threading, time
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
network = _load('network')

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
    'network': 'off',
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
    if data.get('network') in shields.NETWORK_MODES:
        config['network'] = data['network']
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
            if previous.get('network') != current.get('network'):
                mode = current.get('network', 'off')
                log(f'Network {mode.title()}.')
                if mode == 'yeet':
                    log(network.YEET_WARNING)
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
    state.setdefault('pf', {})
    if not isinstance(state['pf'], dict):
        state['pf'] = {}
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


def command(*args, timeout=10):
    try:
        return subprocess.run(args, text=True, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, timeout=timeout)
    except subprocess.TimeoutExpired:
        return subprocess.CompletedProcess(args, 124, '', f'timed out after {timeout}s')

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

def user_launch_agent_scans(uids, homedir=pwd.getpwuid):
    """Per-user ~/Library/LaunchAgents for login uids. Do not follow a symlink folder."""
    scans = []
    for uid in uids:
        if uid < 500:
            continue
        try:
            home = homedir(uid).pw_dir
        except (KeyError, OSError, AttributeError):
            continue
        if not home:
            continue
        folder = Path(home) / 'Library' / 'LaunchAgents'
        try:
            if folder.is_symlink() or not folder.is_dir():
                continue
        except OSError:
            continue
        scans.append((folder, [f'gui/{uid}']))
    return scans


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
    scans.extend(user_launch_agent_scans(uids))
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

def _job_override_disabled(overrides, label):
    return overrides.get(label) in ('true', 'disabled')


def _record_job_current(state, key, **fields):
    with STATE_LOCK:
        if key in state['jobs']:
            state['jobs'][key].update(fields)
            save_state(state)


def block_jobs(state):
    failures, overrides, timed_out = [], {}, set()
    for (domain, label), (path, default_disabled) in jobs().items():
        key = f'{domain}/{label}'
        recorded = state['jobs'].get(key) or {}
        if domain not in overrides:
            status = command('/bin/launchctl', 'print-disabled', domain, timeout=3)
            if status.returncode == 124:
                overrides[domain] = {}
                timed_out.add(domain)
            elif status.returncode:
                overrides[domain] = None
                if domain == 'system':
                    failures.append('Cannot read launchd system state')
            else:
                overrides[domain] = dict(re.findall(
                    r'"([^"\n]+)"\s*=>\s*(true|false|disabled|enabled)', status.stdout))
        if overrides[domain] is None and domain not in timed_out:
            continue
        override_map = overrides[domain] or {}
        currently_disabled = _job_override_disabled(override_map, label)
        already_off = recorded.get('current_loaded') is False and (
            currently_disabled or (domain in timed_out and recorded.get('current_disabled')))
        if already_off:
            continue
        printed = command('/bin/launchctl', 'print', key, timeout=3)
        if printed.returncode == 124:
            is_loaded = recorded.get('current_loaded')
            if is_loaded is None:
                is_loaded = recorded.get('loaded', True)
        else:
            is_loaded = printed.returncode == 0
        with STATE_LOCK:
            if key not in state['jobs']:
                original = override_map.get(label) if override_map else None
                state['jobs'][key] = {
                    'disabled': original in ('true', 'disabled') if original is not None else default_disabled,
                    'loaded': is_loaded,
                    'path': path,
                    'current_loaded': is_loaded,
                    'current_disabled': currently_disabled,
                }
                save_state(state)
        need_disable = not currently_disabled and not recorded.get('current_disabled')
        if domain in timed_out:
            need_disable = not recorded.get('current_disabled')
        if need_disable:
            action = command('/bin/launchctl', 'disable', key)
            if action.returncode == 124:
                pass
            elif action.returncode:
                failures.append(f'Could not disable {key}: {action.stderr.strip()}')
                continue
            else:
                log(f'Launch job disabled: {key}')
                _record_job_current(state, key, current_disabled=True)
        if is_loaded:
            action = command('/bin/launchctl', 'bootout', key)
            if action.returncode == 124:
                pass
            elif action.returncode:
                still = command('/bin/launchctl', 'print', key, timeout=3)
                if still.returncode == 0:
                    failures.append(f'Could not unload {key}: {action.stderr.strip()}')
            else:
                log(f'Launch job unloaded: {key}')
                _record_job_current(state, key, current_loaded=False)
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
    failures = restore_modes(state) + restore_jobs(state)
    failures.extend(sync_network('off', state))
    return failures


def sync_network(mode, state, announce=True):
    try:
        failures, _commands = network.sync(
            mode, ROOT, state, policy_path=ROOT / 'network_policy.json',
            kill_states=announce and mode != 'off')
    except (OSError, ValueError, TypeError, subprocess.TimeoutExpired) as error:
        return [str(error)]
    messages = [item for item in failures if item]
    try:
        save_state(state)
    except OSError as error:
        messages.append(f'Could not save network undo record: {error}')
    if announce and mode in ('on', 'yeet') and not messages:
        log('Network rules loaded.')
        if network.read_status(ROOT).get('stale'):
            log('Network resolution failed.')
    return messages


def should_sync_network(mode, applied, last_network, now, interval=60):
    """Apply when the shield mode differs from the last PF sync, or when DNS refresh is due.

    refresh_shields() can be consumed by the permission loop, so this compares
    against the last mode this thread actually loaded into PF.
    """
    changed = applied != mode
    refresh = mode != 'off' and last_network > 0 and now - last_network >= interval
    return changed or refresh, changed


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
        self.last_network = 0.0
        self.applied_network = 'off'

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
                mode = current.get('network', 'off')
                needed, announce = should_sync_network(
                    mode, self.applied_network, self.last_network, time.monotonic())
                if needed:
                    for failure in sync_network(mode, self.state, announce=announce):
                        log('PROTECTION ERROR: ' + failure)
                    self.last_network = time.monotonic()
                    self.applied_network = mode
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
        if SHIELDS.get('network') == 'yeet':
            log(network.YEET_WARNING)
        supervise()
        if '--once' in sys.argv:
            failures = []
            if SHIELDS['permissions']:
                failures.extend(block_modes(state, executables()))
            if SHIELDS['jobs']:
                failures.extend(block_jobs(state))
            failures.extend(sync_network(
                SHIELDS.get('network', 'off'), state,
                announce=SHIELDS.get('network', 'off') != 'off'))
            for failure in failures: log('PROTECTION ERROR: ' + failure)
            return bool(failures)
        for failure in sync_network(
                SHIELDS.get('network', 'off'), state,
                announce=SHIELDS.get('network', 'off') != 'off'):
            log('PROTECTION ERROR: ' + failure)
        background = BackgroundChecks(state, stop_event)
        background.applied_network = SHIELDS.get('network', 'off')
        if background.applied_network != 'off':
            background.last_network = time.monotonic()
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
