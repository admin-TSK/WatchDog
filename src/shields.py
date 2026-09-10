"""Runtime shield toggles for WatchDog's local controls.

The menu bar writes a JSON request into the world-writable drop folder. The
root event reader copies accepted values into the guard's shields.json. The
guard reloads that file on each loop. Jamf Connect stays off until enabled.
Network is Off / On / Yeet, not a boolean.
"""
import json
import os
from pathlib import Path

KEYS = ('permissions', 'jobs', 'monitor', 'sticky', 'signatures', 'connect')
CORE = ('permissions', 'jobs', 'monitor')
NETWORK_MODES = ('off', 'on', 'yeet')
DEFAULTS = {
    'permissions': True,
    'jobs': True,
    'monitor': True,
    'sticky': False,
    'signatures': False,
    'connect': False,
    'network': 'off',
}


def network_mode(value, fallback='off'):
    if value in NETWORK_MODES:
        return value
    if value in (False, 0, '0', 'false', 'False', None):
        return 'off'
    if value in (True, 1, '1', 'true', 'True'):
        return 'on'
    return fallback if fallback in NETWORK_MODES else 'off'


def from_config(config=None):
    data = dict(DEFAULTS)
    if not config:
        return data
    data['sticky'] = bool(config.get('sticky_block', False))
    data['signatures'] = bool(config.get('match_signature', False))
    data['connect'] = bool(config.get('block_connect', False))
    data['network'] = network_mode(config.get('network', 'off'))
    return data


def normalize(value, config=None):
    data = from_config(config)
    if isinstance(value, dict):
        for key in KEYS:
            if key in value:
                data[key] = bool(value[key])
        if 'network' in value:
            data['network'] = network_mode(value['network'], data['network'])
    return data


def load(path, config=None):
    path = Path(path)
    if not path.exists():
        return from_config(config)
    try:
        return normalize(json.loads(path.read_text()), config)
    except (OSError, ValueError, TypeError):
        return from_config(config)


def save(path, data):
    path = Path(path)
    payload = normalize(data)
    temporary = path.with_suffix('.tmp')
    with open(temporary, 'w') as stream:
        os.chmod(temporary, 0o600)
        json.dump(payload, stream, indent=2)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)
    return payload


def apply(current, request):
    """Apply one menu-bar request: {'id': 'permissions', 'enabled': false} or {'id': 'network', 'mode': 'yeet'}."""
    data = normalize(current)
    if not isinstance(request, dict):
        return data
    key = request.get('id')
    if key in KEYS and 'enabled' in request:
        data[key] = bool(request['enabled'])
    elif key == 'network':
        if 'mode' in request:
            data['network'] = network_mode(request.get('mode'))
        elif request.get('enabled') is False:
            data['network'] = 'off'
    return data
