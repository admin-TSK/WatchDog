#!/usr/bin/env python3
"""Publish a small, read-only activity feed for the unprivileged menu bar app."""
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import time

ROOT = Path(__file__).resolve().parent
PUBLIC = Path('/Library/Application Support/WatchDog Status')
STOP = False
MAX_EVENTS = 100


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
    elif line.startswith('Execution blocked: '):
        name = Path(line.removeprefix('Execution blocked: ').strip()).name
        # The feed never carries private file paths or arbitrary root-log content.
        name = re.sub(r'[^a-zA-Z0-9 ._-]', '', name)[:80]
        event.update(kind='permission', title='Execution permission blocked', detail=name or 'Jamf framework executable')
    elif line.startswith(('Launch job disabled: ', 'Launch job unloaded: ')):
        value = line.split(': ', 1)[1].strip().rsplit('/', 1)[-1]
        if not re.fullmatch(r'com\.jamf(?:software|\.management)\.[a-zA-Z0-9_.-]+', value):
            return None
        event.update(kind='job', title='Background job '+('disabled' if 'disabled:' in line else 'unloaded'), detail=value)
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

    def read(self, path, now):
        try:
            with open(path, 'rb') as stream:
                stat = os.fstat(stream.fileno())
                signature = f'{stat.st_dev}:{stat.st_ino}'
                previous = self.cursor
                historical = not previous
                reset = previous.get('inode') != signature or previous.get('offset', 0) > stat.st_size
                offset = max(0, stat.st_size - 262144) if reset else previous['offset']
                stream.seek(offset)
                if reset and offset:
                    stream.readline()  # Drop a partial leading line.
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
                        self.events.append(event)
                        self.events = self.events[-MAX_EVENTS:]
                        self.action_total += 1
                        self.process_total += int(event['kind'] == 'process')
                self.cursor = {'inode': signature, 'offset': stream.tell()}
        except FileNotFoundError:
            pass

    def saved(self):
        return {'events': self.events, 'cursor': self.cursor, 'process_total': self.process_total, 'action_total': self.action_total}


def health(config):
    result = subprocess.run(['/bin/launchctl', 'print', f'system/{config["guard_label"]}'], capture_output=True, text=True, timeout=5)
    running = result.returncode == 0 and 'state = running' in result.stdout
    pid = re.search(r'^\s*pid = (\d+)', result.stdout, re.MULTILINE)
    process_list = subprocess.run(['/bin/ps', '-axo', 'ppid=,comm='], capture_output=True, text=True, timeout=5).stdout
    monitor = False
    for line in process_list.splitlines():
        fields = line.strip().split(None, 1)
        if len(fields) == 2 and pid and fields[0] == pid[1] and fields[1] in config['monitor_paths']:
            monitor = True
    binary = Path('/usr/local/jamf/bin/jamf')
    permissions = not binary.exists() or os.stat(binary).st_mode & 0o111 == 0
    state = json.loads((Path(config['guard_root']) / 'state.json').read_text())
    return {'guard_running': running, 'monitor_running': monitor, 'execution_blocked': permissions,
            'executable_count': len(state.get('modes', {})), 'job_count': len(state.get('jobs', {}))}


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
    while not STOP:
        now = time.time()
        try:
            feed.read(config['log_path'], now)
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
            print(f'WatchDog activity feed error: {type(error).__name__}', flush=True)
            # Do not renew a healthy heartbeat when collection has failed.
        time.sleep(1)


if __name__ == '__main__':
    main()
