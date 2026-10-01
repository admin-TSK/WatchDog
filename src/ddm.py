"""Jamf Blueprint / DDM shield catalog.

Software update is the only applied state WatchDog removes, and only after a
write-once snapshot. Installs and assets contribute hostnames, never URLs.
"""
import base64
import os
import re
import stat
from urllib.parse import urlparse

SOFTWARE_UPDATE_PATH = '/var/db/softwareupdate/SoftwareUpdateDDMStatePersistence.plist'
MAX_SNAPSHOT = 256 * 1024
HOST_CAP = 32
MARKER = (
    b'<?xml version="1.0" encoding="UTF-8"?>\n'
    b'<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" '
    b'"http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n'
    b'<plist version="1.0"><dict><key>WatchDog</key>'
    b'<string>softwareupdate-removed</string></dict></plist>\n'
)
TYPE_RE = re.compile(r'com\.apple\.(?:configuration|asset)\.[A-Za-z0-9._-]+')
URL_RE = re.compile(r'https?://[^\s\'"<>]+', re.I)
IMMUTABLE = getattr(stat, 'UF_IMMUTABLE', 0x00000002)

CATALOG = (
    ('com.apple.configuration.softwareupdate.', 'remove'),
    ('com.apple.configuration.app.managed', 'restrict'),
    ('com.apple.configuration.passcode.', 'not_removed'),
    ('com.apple.configuration.diskmanagement.', 'not_removed'),
    ('com.apple.configuration.safari.', 'not_removed'),
    ('com.apple.configuration.math.', 'not_removed'),
    ('com.apple.asset.', 'restrict'),
)

UPDATE_WARNING = (
    'Software update downloads pause while this shield is on, including updates you start yourself.'
)
INSTALL_WARNING = (
    'App and package downloads pause. Apps and packages already on disk stay installed.'
)
PUSH_WARNING = (
    'Management wake blocks Apple Push ranges. iMessage and other push services will break. Enrollment stays.'
)


def action_for(declaration_type):
    text = declaration_type or ''
    for prefix, action in CATALOG:
        if text.startswith(prefix):
            return action
    return 'not_removed'


def declaration_types(blob):
    if isinstance(blob, bytes):
        blob = blob.decode('utf-8', errors='ignore')
    if not isinstance(blob, str):
        return []
    found = []
    for match in TYPE_RE.findall(blob):
        if match not in found:
            found.append(match)
    return found


def endpoint_from_url(value):
    """Return (host, port). Host only; no path, query, or userinfo."""
    if not value or not isinstance(value, str):
        return None
    text = value.strip().strip('"')
    if '://' not in text:
        text = 'https://' + text
    parsed = urlparse(text)
    host = (parsed.hostname or '').strip().rstrip('.').lower()
    if not host:
        return None
    if host.startswith('*.'):
        return '*', 443
    try:
        port = int(parsed.port) if parsed.port is not None else 443
    except (TypeError, ValueError):
        port = 443
    if port < 1 or port > 65535:
        port = 443
    return host, port


def hosts_from_blob(blob, cap=HOST_CAP):
    """Concrete hosts, plus a partial marker when a URL is only a wildcard."""
    if isinstance(blob, bytes):
        blob = blob.decode('utf-8', errors='ignore')
    if not isinstance(blob, str):
        return [], []
    hosts, partial = [], []
    for match in URL_RE.findall(blob):
        endpoint = endpoint_from_url(match.rstrip(').,;'))
        if endpoint is None:
            continue
        host, _port = endpoint
        if host == '*':
            if 'wildcard' not in partial:
                partial.append('wildcard')
            continue
        if host not in hosts:
            hosts.append(host)
        if len(hosts) >= cap:
            break
    return hosts, partial


def wants_channel(shields, record=None):
    shields = shields or {}
    record = record or {}
    if shields.get('ddm-channel') or shields.get('ddm-update') or shields.get('ddm-installs'):
        return True
    return _snapshot_saved(record.get('softwareupdate'))


def extra_groups(policy, shields, manifest_hosts=()):
    """Groups to add even when Network is Off. Never an empty all-hosts group."""
    shields = shields or {}
    by_id = {group['id']: group for group in policy.get('groups', [])}
    selected = []

    def add(identity):
        group = by_id.get(identity)
        if group and group not in selected:
            selected.append(group)

    if wants_channel(shields):
        add('jamf-management')
    if shields.get('ddm-push'):
        add('apns')
    if shields.get('ddm-update'):
        add('apple-software-update')
    if shields.get('ddm-installs'):
        add('apple-app-store')
    hosts = []
    for host in manifest_hosts or ():
        if not isinstance(host, str):
            continue
        cleaned = host.strip().rstrip('.').lower()
        if not cleaned or cleaned.startswith('*.') or '/' in cleaned or cleaned in hosts:
            continue
        hosts.append(cleaned)
        if len(hosts) >= HOST_CAP:
            break
    if hosts and (shields.get('ddm-installs') or shields.get('ddm-assets')):
        selected.append({
            'id': 'ddm-manifests',
            'modes': (),
            'direction': 'out',
            'transport': 'tcp',
            'ports': (443,),
            'hosts': hosts,
            'cidrs': [],
            'discover': None,
        })
    return selected


def pf_token(network_mode, shields, record=None):
    shields = shields or {}
    bits = []
    if wants_channel(shields, record):
        bits.append('channel')
    if shields.get('ddm-push'):
        bits.append('push')
    if shields.get('ddm-update'):
        bits.append('update')
    if shields.get('ddm-installs'):
        bits.append('installs')
    if shields.get('ddm-assets'):
        bits.append('assets')
    mode = network_mode if network_mode in ('on', 'yeet') else 'off'
    if mode == 'off' and not bits:
        return 'off'
    return mode + ('+' + ','.join(bits) if bits else '')


def _read_regular(path):
    """Return ('absent', None, None), ('ok', bytes, stat), or ('refused', None, None)."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except FileNotFoundError:
        return 'absent', None, None
    except OSError:
        return 'refused', None, None
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_SNAPSHOT:
            return 'refused', None, None
        return 'ok', os.read(fd, MAX_SNAPSHOT + 1), info
    finally:
        os.close(fd)


def _snapshot_saved(slot):
    return isinstance(slot, dict) and ('content_b64' in slot or slot.get('absent'))


def capture_snapshot(record, path):
    """Store original bytes once. Does not write the marker."""
    slot = record.get('softwareupdate')
    if _snapshot_saved(slot):
        return 'snapshotted'
    kind, data, info = _read_regular(path)
    if kind == 'refused':
        return 'not_removed'
    if kind == 'absent':
        record['softwareupdate'] = {'absent': True}
        return 'snapshotted'
    if data is None or len(data) > MAX_SNAPSHOT:
        return 'not_removed'
    record['softwareupdate'] = {
        'absent': False,
        'content_b64': base64.b64encode(data).decode('ascii'),
        'mode': stat.S_IMODE(info.st_mode),
        'flags': int(getattr(info, 'st_flags', 0)),
    }
    return 'snapshotted'


def _write_bytes(path, payload, mode):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW, 0o644)
    try:
        info = os.fstat(fd)
        current = int(getattr(info, 'st_flags', 0))
        if current & IMMUTABLE:
            os.chflags(path, current & ~IMMUTABLE)
        os.ftruncate(fd, 0)
        os.write(fd, payload)
        os.fsync(fd)
        os.fchmod(fd, mode)
    finally:
        os.close(fd)


def hold_software_update(record, path):
    """Return (status, rewrote). An absent snapshot is left untouched."""
    slot = record.get('softwareupdate')
    if not _snapshot_saved(slot):
        return 'not_removed', False
    if slot.get('absent'):
        return 'restricted', False
    kind, data, _info = _read_regular(path)
    if kind == 'refused':
        return 'removal_failed', False
    current = b'' if kind == 'absent' or data is None else data
    if current == MARKER:
        return 'removed', False
    try:
        _write_bytes(path, MARKER, 0o644)
    except OSError:
        return 'removal_failed', False
    return 'removed', True


def revert_software_update(record, path):
    """Write the snapshot back. Return an error string, or None."""
    slot = record.get('softwareupdate')
    if not _snapshot_saved(slot) or slot.get('absent'):
        return None
    try:
        original = base64.b64decode(slot.get('content_b64') or '', validate=True)
    except (ValueError, TypeError):
        return 'software update snapshot is unreadable'
    try:
        _write_bytes(path, original, int(slot.get('mode') or 0o644))
        flags = int(slot.get('flags') or 0)
        if flags:
            os.chflags(path, flags)
    except OSError as error:
        return str(error)
    return None


def public_status(shields, record, network_mode='off', management_ready=False):
    """Status for the activity feed. No file bytes, paths, or URLs."""
    shields = shields or {}
    record = record if isinstance(record, dict) else {}
    forced = bool(
        shields.get('ddm-update') or shields.get('ddm-installs')
        or _snapshot_saved(record.get('softwareupdate'))
    )
    tiles = {}
    if forced and not shields.get('ddm-channel'):
        tiles['ddm-channel'] = 'forced'
    elif shields.get('ddm-channel') or forced:
        ready = management_ready or network_mode in ('on', 'yeet')
        if network_mode in ('on', 'yeet') and not shields.get('ddm-channel') and not (
                shields.get('ddm-update') or shields.get('ddm-installs')):
            tiles['ddm-channel'] = 'covered'
        elif forced and not shields.get('ddm-channel'):
            tiles['ddm-channel'] = 'forced'
        else:
            tiles['ddm-channel'] = 'restricted' if ready else 'partial'
    if shields.get('ddm-push'):
        tiles['ddm-push'] = 'covered' if network_mode == 'yeet' else 'restricted'
    if shields.get('ddm-update'):
        tiles['ddm-update'] = record.get('softwareupdate_status') or 'restricted'
    elif record.get('softwareupdate_status') == 'reverted':
        tiles['ddm-update'] = 'reverted'
    if shields.get('ddm-installs'):
        tiles['ddm-installs'] = 'restricted'
    if shields.get('ddm-assets'):
        tiles['ddm-assets'] = 'partial' if record.get('asset_partial') else 'restricted'
    types = [item for item in record.get('types') or [] if isinstance(item, str) and TYPE_RE.fullmatch(item)]
    return {'tiles': tiles, 'types': types[:12]}
