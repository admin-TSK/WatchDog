#!/usr/bin/env python3
"""Publish a small, read-only activity feed for the unprivileged menu bar app."""
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import stat
import subprocess
import time

import importlib.util
import sys
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
PUBLIC = Path('/Library/Application Support/WatchDog Status')
REQUESTS = PUBLIC / 'requests'
STOP = False
MAX_EVENTS = 100
JOB_LABEL = re.compile(r'^com\.jamf(?:software|\.management|\.connect|\.appinstallers|\.selfservice)[a-zA-Z0-9_.]*$')


def atomic_json(path, value, mode):
    temporary = path.with_suffix('.tmp')
    with open(temporary, 'w') as stream:
        os.chmod(temporary, mode)
        json.dump(value, stream)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)


def parse_event(line, identity, observed, historical=False):
    """Only fixed event categories and sanitized target names reach the user feed."""
    stamp = re.match(r'^(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d) ', line)
    timestamp = None if historical else observed
    if stamp:
        try:
            timestamp = datetime.datetime.strptime(stamp[1], '%Y-%m-%d %H:%M:%S').timestamp()
        except ValueError:
            pass
        line = line[20:]
    event = {'id': hashlib.sha256(identity.encode()).hexdigest()[:24], 'timestamp': timestamp}
    if match := re.search(r'Killed (?:framework process or observed descendant )?PID (\d+)', line):
        event.update(kind='process', title='Framework process stopped', detail=f'Jamf process or observed child · PID {match[1]}')
    elif line.startswith('Execution blocked: ') or line.startswith('Sticky block applied: '):
        name = Path(line.split(': ', 1)[1].strip()).name
        name = re.sub(r'[^a-zA-Z0-9 ._-]', '', name)[:80]
        title = 'Sticky execution block applied' if line.startswith('Sticky') else 'Execution permission blocked'
        event.update(kind='permission', title=title, detail=name or 'Jamf framework executable')
    elif line.startswith(('Launch job disabled: ', 'Launch job unloaded: ')):
        value = line.split(': ', 1)[1].strip().rsplit('/', 1)[-1]
        if not JOB_LABEL.fullmatch(value):
            return None
        event.update(kind='job', title='Background job '+('disabled' if 'disabled:' in line else 'unloaded'), detail=value)
    elif 'TimeoutExpired' in line and "('/bin/ps', '-axo', 'uid=,comm=')" in line:
        detail = ('Session scan timed out; permission checks continued.'
                  if 'continue independently' in line else
                  'The logged-in session scan exceeded 10 seconds and was skipped.')
        event.update(kind='warning', code='session_scan_timeout', title='Session check timed out', detail=detail)
    elif line == 'Session discovery healthy: native process lookup.':
        event.update(kind='recovery', code='session_scan_timeout')
    elif line.startswith('Shield ') and line.endswith('.'):
        parts = line[7:-1].rsplit(' ', 1)
        if len(parts) != 2 or parts[0] not in {'permissions', 'jobs', 'monitor', 'sticky', 'signatures', 'connect'} or parts[1] not in {'on', 'off'}:
            return None
        event.update(kind='shield', title=f'{parts[0].replace("_", " ").title()} shield {parts[1]}',
                     detail='Local control updated from Shields.')
    elif line in {'Network Off.', 'Network On.', 'Network Yeet.'}:
        event.update(kind='shield', title=line[:-1], detail='Outbound filter updated from Shields.')
    elif line == 'Network rules loaded.':
        event.update(kind='shield', title='Network rules loaded', detail='A loaded rule is not a confirmed deny.')
    elif line == 'Network resolution failed.':
        event.update(kind='warning', title='Network resolution failed', detail='Some hostnames could not be resolved into addresses.')
    elif line == 'Network hostname partial.':
        return None
    elif line.startswith('PROTECTION ERROR: Existing Jamf connections were not reset'):
        event.update(kind='warning', title='Existing Jamf connections were not reset',
                     detail='Outbound deny rules were applied; some Jamf sockets were not reset.')
    elif line.startswith('PROTECTION ERROR: Background status check timed out') and "'-k'" in line:
        event.update(kind='warning', title='Packet filter state kill timed out',
                     detail='Existing connections were not reset; outbound deny rules were still applied.')
    elif line.startswith('PROTECTION ERROR: Background status check timed out') and 'launchctl' in line:
        event.update(kind='warning', title='Launch job check timed out',
                     detail='WatchDog will retry disabling matching launch jobs.')
    elif line.startswith('PROTECTION ERROR:') and (
            'Could not release the packet filter enable token' in line or
            'Packet filter enable did not return a token' in line or
            'option requires an argument -- X' in line):
        event.update(kind='error', title='Packet filter token missing',
                     detail='Network Off must pass the token from pfctl -E to pfctl -X.')
    elif line.startswith('PROTECTION ERROR: Could not enable the packet filter'):
        event.update(kind='error', title='Packet filter enable failed',
                     detail='WatchDog could not increment the PF enable count.')
    elif line.startswith('PROTECTION ERROR: Could not flush the WatchDog packet-filter anchor'):
        event.update(kind='error', title='Packet filter flush failed',
                     detail='WatchDog could not clear its outbound PF anchor.')
    elif 'PROTECTION ERROR:' in line or line.startswith(('Cannot kill PID ', 'Cannot pause PID ', 'Process enumeration failed')):
        event.update(kind='error', title='A protection action failed', detail='Review the administrator log for details.')
    else:
        return None
    return event


class Feed:
    def __init__(self, saved=None):
        saved = saved or {}
        self.events = saved.get('events', [])[-MAX_EVENTS:]
        self.cursor = saved.get('cursor', {})
        self.process_total = saved.get('process_total', 0)
        self.action_total = saved.get('action_total', 0)
        self.parser_version = saved.get('parser_version', 1)
        self.session_recovered_at = saved.get('session_recovered_at')

    def resolve_session_warnings(self):
        if self.session_recovered_at is None:
            return
        for event in self.events:
            if (event.get('code') == 'session_scan_timeout' and
                    event.get('timestamp') is not None and
                    event['timestamp'] <= self.session_recovered_at):
                event.setdefault('resolved_at', self.session_recovered_at)

    def reclassify(self, path):
        by_id = {event['id']: event for event in self.events}
        with open(path, 'rb') as stream:
            info = os.fstat(stream.fileno())
            signature = f'{info.st_dev}:{info.st_ino}'
            offset = max(0, info.st_size - 262144)
            stream.seek(offset)
            if offset: stream.readline()
            while True:
                start = stream.tell()
                line = stream.readline(65537)
                if not line or not line.endswith(b'\n'): break
                event = parse_event(line.decode('utf-8', errors='replace').strip(),
                                    f'{signature}:{start}', 0, historical=True)
                if event and event['kind'] == 'recovery' and event['timestamp'] is not None:
                    self.session_recovered_at = max(self.session_recovered_at or 0, event['timestamp'])
                if event and event['id'] in by_id:
                    original = by_id[event['id']]
                    original.update({key: event[key] for key in ('kind', 'title', 'detail', 'code') if key in event})
        self.events = [event for event in self.events if event.get('title') != 'Network hostname partial']
        self.parser_version = 6

    def read(self, path, now):
        try:
            if self.parser_version < 6:
                self.reclassify(path)
            with open(path, 'rb') as stream:
                info = os.fstat(stream.fileno())
                signature = f'{info.st_dev}:{info.st_ino}'
                previous = self.cursor
                historical = not previous
                reset = previous.get('inode') != signature or previous.get('offset', 0) > info.st_size
                offset = max(0, info.st_size - 262144) if reset else previous['offset']
                stream.seek(offset)
                if reset and offset:
                    stream.readline()
                while True:
                    start = stream.tell()
                    data = stream.readline(65537)
                    if not data:
                        break
                    if not data.endswith(b'\n'):
                        stream.seek(start)
                        break
                    line = data.decode('utf-8', errors='replace').strip()
                    event = parse_event(line, f'{signature}:{start}', now, historical)
                    if event:
                        if event['kind'] == 'recovery':
                            if event['timestamp'] is not None:
                                self.session_recovered_at = max(self.session_recovered_at or 0, event['timestamp'])
                        else:
                            self.events.append(event)
                            self.events = self.events[-MAX_EVENTS:]
                            self.action_total += 1
                            self.process_total += int(event['kind'] == 'process')
                self.cursor = {'inode': signature, 'offset': stream.tell()}
                self.resolve_session_warnings()
        except FileNotFoundError:
            pass

    def saved(self):
        return {'parser_version': self.parser_version, 'session_recovered_at': self.session_recovered_at,
                'events': self.events, 'cursor': self.cursor, 'process_total': self.process_total, 'action_total': self.action_total}


def consume_shield_requests(guard_root):
    """Apply menu-bar shield requests into the guard's shields.json."""
    path = Path(guard_root) / 'shields.json'
    current = shields.load(path)
    try:
        REQUESTS.mkdir(parents=True, exist_ok=True)
        os.chmod(REQUESTS, 0o1777)
        items = sorted(REQUESTS.glob('*.json'))
    except OSError:
        return current
    changed = False
    for item in items:
        try:
            if item.is_symlink() or not item.is_file() or item.stat().st_size > 4096:
                pass
            else:
                current = shields.apply(current, json.loads(item.read_text()))
                changed = True
        except (OSError, ValueError, TypeError):
            pass
        try:
            item.unlink()
        except OSError:
            pass
    if changed:
        try:
            shields.save(path, current)
        except OSError:
            pass
    return current


def execute_cleared(path):
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        return True
    if stat.S_ISLNK(info.st_mode):
        return True
    return info.st_mode & 0o111 == 0


def health(config):
    result = subprocess.run(['/bin/launchctl', 'print', f'system/{config["guard_label"]}'], capture_output=True, text=True, timeout=5)
    running = result.returncode == 0 and 'state = running' in result.stdout
    pid = re.search(r'^\s*pid = (\d+)', result.stdout, re.MULTILINE)
    monitor = bool(pid) and processes.has_child(int(pid[1]), config['monitor_paths'])
    state_file = Path(config['guard_root']) / 'state.json'
    state = json.loads(state_file.read_text()) if state_file.exists() else {}
    paths = {Path(p) for p in targets.EXACT_PATHS}
    paths.update(Path(p) for p in state.get('modes', {}))
    permissions = all(execute_cleared(path) for path in paths)
    runtime = shields.load(Path(config['guard_root']) / 'shields.json')
    return {'guard_running': running, 'monitor_running': monitor, 'execution_blocked': permissions,
            'executable_count': len(state.get('modes', {})), 'job_count': len(state.get('jobs', {})),
            'shields': runtime, 'network': network.read_status(config['guard_root'])}


def heal_guard(config, now, last_attempt, minimum=60):
    """Re-bootstrap the guard at most once per minute when it is not running."""
    if now - last_attempt < minimum:
        return last_attempt, False
    plist = Path('/Library/LaunchDaemons') / f'{config["guard_label"]}.plist'
    if not plist.exists():
        return now, False
    subprocess.run(['/bin/launchctl', 'bootstrap', 'system', str(plist)], capture_output=True, text=True, timeout=10)
    return now, True


def main():
    global STOP
    if os.geteuid() != 0:
        raise SystemExit('The WatchDog event bridge must run as root.')
    os.umask(0o077)
    def stop(signum, frame):
        global STOP
        STOP = True
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    config = json.loads((ROOT / 'config.json').read_text())
    state_path = ROOT / 'feed-state.json'
    feed = Feed(json.loads(state_path.read_text()) if state_path.exists() else None)
    previous = None
    last_heal = 0
    while not STOP:
        now = time.time()
        try:
            feed.read(config['log_path'], now)
            consume_shield_requests(config['guard_root'])
            state = health(config)
            if not state['guard_running']:
                last_heal, attempted = heal_guard(config, now, last_heal)
                if attempted:
                    print('WatchDog activity feed: attempted guard restart.', flush=True)
                    state = health(config)
            snapshot = {'schema': 1, 'updated_at': now, **state,
                        'events': list(reversed(feed.events)), 'process_total': feed.process_total,
                        'action_total': feed.action_total}
            saved = feed.saved()
            if saved != previous:
                atomic_json(state_path, saved, 0o600)
                previous = json.loads(json.dumps(saved))
            atomic_json(PUBLIC / 'events.json', snapshot, 0o644)
        except Exception as error:
            print(f'WatchDog activity feed error: {error!r}', flush=True)
        time.sleep(1)


if __name__ == '__main__':
    main()
