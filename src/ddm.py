"""Jamf Blueprint / DDM shield catalog.

Software update is the only applied state WatchDog edits. It deletes a scheduled
OS enforcement and the OS-upgrade keys, then puts just those entries back.
Installs and assets contribute hostnames, never URLs, and never a shared CDN.
"""
import base64
import copy
import os
import plistlib
import re
import stat
import tempfile
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
    'Removes a managed OS update record from the software update file. '
    'Security updates stay. Apple update servers stay open. '
    'A schedule already loaded by softwareupdated may remain until that process reloads.'
)
INSTALL_WARNING = (
    'No Blueprint package host is visible, so downloads are not blocked. The App Store stays open.'
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


SHARED_SUFFIXES = (
    'apple.com', 'cdn-apple.com', 'icloud.com', 'mzstatic.com', 'itunes.com',
    'amazonaws.com', 'cloudfront.net', 'akamaihd.net', 'fastly.net',
)


def _normal_host(host):
    if not isinstance(host, str):
        return ''
    return host.strip().rstrip('.').lower()


def shared_host(host):
    """True for App Store, software update, iCloud, and Apple Push names."""
    host = _normal_host(host)
    return any(host == suffix or host.endswith('.' + suffix) for suffix in SHARED_SUFFIXES)


def management_host(host, management_hosts=()):
    host = _normal_host(host)
    for item in management_hosts or ():
        base = _normal_host(item)
        if base and (host == base or host.endswith('.' + base)):
            return True
    return False


def usable_host(host, management_hosts=()):
    """A deny target must be a concrete declaration host that normal Mac use does not share."""
    host = _normal_host(host)
    if not host or host.startswith('*.') or '/' in host:
        return False
    if shared_host(host) or management_host(host, management_hosts):
        return False
    return True


def partition_hosts(hosts, management_hosts=()):
    """Return (deny_hosts, partial_reasons). Empty deny_hosts is not all hosts."""
    kept, partial = [], []
    for host in hosts or ():
        cleaned = _normal_host(host)
        if not cleaned or cleaned.startswith('*.') or '/' in cleaned:
            if 'wildcard' not in partial:
                partial.append('wildcard')
            continue
        if shared_host(cleaned):
            if 'shared' not in partial:
                partial.append('shared')
            continue
        if management_host(cleaned, management_hosts):
            if 'management' not in partial:
                partial.append('management')
            continue
        if cleaned not in kept:
            kept.append(cleaned)
        if len(kept) >= HOST_CAP:
            break
    return kept, partial


def wants_channel(shields, record=None):
    """DDM shields never deny the Jamf server. Check-in and declaration sync share that host."""
    del shields, record
    return False


def extra_groups(policy, shields, manifest_hosts=(), management_hosts=()):
    """Declaration-only denies. Never App Store, update CDN, APNs, or the Jamf host."""
    del policy
    shields = shields or {}
    if not (shields.get('ddm-installs') or shields.get('ddm-assets')):
        return []
    kept, _partial = partition_hosts(manifest_hosts, management_hosts)
    if not kept:
        return []
    return [{
        'id': 'ddm-manifests',
        'modes': (),
        'direction': 'out',
        'transport': 'tcp',
        'ports': (443,),
        'hosts': kept,
        'cidrs': [],
        'discover': None,
    }]


def pf_token(network_mode, shields, record=None):
    shields = shields or {}
    bits = []
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
    return isinstance(slot, dict) and (
        slot.get('seen') or slot.get('absent') or slot.get('rewrote_ever') or 'content_b64' in slot)


def capture_snapshot(record, path):
    """Remember that the file was seen. Does not keep a rollback copy."""
    slot = record.get('softwareupdate')
    if _snapshot_saved(slot):
        return 'snapshotted'
    kind, data, info = _read_regular(path)
    if kind == 'refused':
        return 'not_removed'
    if kind == 'absent':
        record['softwareupdate'] = {'absent': True, 'seen': True, 'rewrote_ever': False}
        return 'snapshotted'
    if data is None or len(data) > MAX_SNAPSHOT:
        return 'not_removed'
    record['softwareupdate'] = {
        'absent': False,
        'seen': True,
        'rewrote_ever': False,
        'mode': stat.S_IMODE(info.st_mode),
        'flags': int(getattr(info, 'st_flags', 0)),
        'uid': info.st_uid,
        'gid': info.st_gid,
    }
    return 'snapshotted'


def _write_bytes(path, payload, mode, uid=None, gid=None):
    """Replace a regular file atomically. Refuse a symlink. Keep mode and owner."""
    path = os.fspath(path)
    try:
        current_info = os.lstat(path)
    except FileNotFoundError:
        current_info = None
    else:
        if stat.S_ISLNK(current_info.st_mode):
            raise OSError('refusing to write through a symbolic link')
        flags = int(getattr(current_info, 'st_flags', 0))
        if flags & IMMUTABLE:
            os.chflags(path, flags & ~IMMUTABLE)
    directory = os.path.dirname(path) or '.'
    fd, temporary = tempfile.mkstemp(prefix='.watchdog-su-', dir=directory)
    try:
        os.write(fd, payload)
        os.fsync(fd)
        os.fchmod(fd, mode)
        if uid is not None and gid is not None:
            try:
                os.fchown(fd, int(uid), int(gid))
            except OSError:
                pass
        os.close(fd)
        fd = None
        os.replace(temporary, path)
        temporary = None
        if current_info is not None:
            kept = int(getattr(current_info, 'st_flags', 0)) & ~IMMUTABLE
            if kept:
                os.chflags(path, kept)
    finally:
        if fd is not None:
            os.close(fd)
        if temporary is not None:
            try:
                os.unlink(temporary)
            except OSError:
                pass


ENFORCEMENT_KEYS = ('TargetOSVersion', 'TargetBuildVersion', 'TargetLocalDateTime')
OS_UPGRADE_KEYS = ('automaticallyInstallOSUpdates', 'enableGlobalNotifications', 'serializedKeys')


def _settings_clean(fields):
    declarations = fields.get('Declarations') if isinstance(fields, dict) else None
    if isinstance(declarations, dict):
        for value in declarations.values():
            if isinstance(value, dict) and any(item in value for item in ENFORCEMENT_KEYS):
                return False
    settings = fields.get('SUCoreDDMDeclarationGlobalSettings') if isinstance(fields, dict) else None
    if isinstance(settings, dict) and any(key in settings for key in OS_UPGRADE_KEYS):
        return False
    return True


def without_enforcement(data):
    """Drop scheduled OS enforcement and OS-upgrade keys. Leave security updates alone.

    Returns (new_bytes, detail). new_bytes is None when data is not a plist dict.
    detail['changed'] is true when an entry was deleted. detail['clean'] means the
    result has no target-version declaration and none of the OS-upgrade keys.
    Security, Rapid Security Response, and download keys are not touched.
    """
    try:
        root = plistlib.loads(data)
    except (ValueError, TypeError, plistlib.InvalidFileException):
        return None, None
    if not isinstance(root, dict):
        return None, None
    fields = root.get('SUCorePersistedStatePolicyFields')
    if not isinstance(fields, dict):
        return data, {'changed': False, 'clean': True, 'declarations': {}, 'globals': {}}
    removed_declarations = {}
    declarations = fields.get('Declarations')
    if isinstance(declarations, dict):
        for key, value in list(declarations.items()):
            if isinstance(value, dict) and any(item in value for item in ENFORCEMENT_KEYS):
                removed_declarations[key] = copy.deepcopy(value)
                del declarations[key]
    removed_globals = {}
    settings = fields.get('SUCoreDDMDeclarationGlobalSettings')
    if isinstance(settings, dict):
        for key in OS_UPGRADE_KEYS:
            if key in settings:
                removed_globals[key] = copy.deepcopy(settings.pop(key))
    changed = bool(removed_declarations or removed_globals)
    detail = {
        'changed': changed,
        'clean': _settings_clean(fields),
        'declarations': removed_declarations,
        'globals': removed_globals,
    }
    if not changed:
        return data, detail
    return plistlib.dumps(root, fmt=plistlib.FMT_BINARY), detail


def _load_removed(slot):
    raw = slot.get('removed_b64') if isinstance(slot, dict) else None
    if not raw:
        return {}, {}
    try:
        parsed = plistlib.loads(base64.b64decode(raw, validate=True))
    except (ValueError, TypeError, plistlib.InvalidFileException):
        return {}, {}
    if not isinstance(parsed, dict):
        return {}, {}
    declarations = parsed.get('declarations') if isinstance(parsed.get('declarations'), dict) else {}
    settings = parsed.get('globals') if isinstance(parsed.get('globals'), dict) else {}
    return declarations, settings


def _store_removed(slot, declarations, settings):
    blob = plistlib.dumps(
        {'declarations': declarations, 'globals': settings}, fmt=plistlib.FMT_BINARY)
    if len(blob) > MAX_SNAPSHOT:
        raise OSError('removed software update entries exceed the snapshot limit')
    slot['removed_b64'] = base64.b64encode(blob).decode('ascii')


def observed_types(path):
    kind, data, _info = _read_regular(path)
    if kind != 'ok' or not data or data == MARKER:
        return []
    return declaration_types(data)


def hold_software_update(record, path):
    """Return (status, rewrote). Deletes OS enforcement; does not replace the file."""
    slot = record.get('softwareupdate')
    if not _snapshot_saved(slot):
        return 'not_removed', False
    kind, data, info = _read_regular(path)
    if kind == 'refused':
        return 'removal_failed', False
    if kind == 'absent' or data is None:
        return 'restricted', False
    updated, detail = without_enforcement(data)
    if detail is None or updated is None:
        return 'not_removed', False
    slot['absent'] = False
    slot['seen'] = True
    if not detail['changed']:
        return ('removed' if detail['clean'] else 'not_removed'), False
    declarations, settings = _load_removed(slot)
    declarations.update(detail['declarations'])
    settings.update(detail['globals'])
    try:
        mode = stat.S_IMODE(info.st_mode) if info is not None else int(slot.get('mode') or 0o644)
        uid = info.st_uid if info is not None else slot.get('uid')
        gid = info.st_gid if info is not None else slot.get('gid')
        _write_bytes(path, updated, mode, uid, gid)
        _store_removed(slot, declarations, settings)
    except OSError:
        return 'removal_failed', False
    slot['rewrote_ever'] = True
    if info is not None:
        slot['mode'] = stat.S_IMODE(info.st_mode)
        slot['flags'] = int(getattr(info, 'st_flags', 0))
        slot['uid'] = info.st_uid
        slot['gid'] = info.st_gid
    return 'removed', True


def revert_software_update(record, path):
    """Put removed entries back into the current file. Never write an old copy.

    Return an error string, or None. A shield that never rewrote the file is a no-op.
    A missing file is left missing. A key the daemon already has is left alone.
    """
    slot = record.get('softwareupdate')
    if not isinstance(slot, dict) or not slot.get('rewrote_ever'):
        return None
    declarations, settings = _load_removed(slot)
    if not declarations and not settings:
        return None
    kind, data, info = _read_regular(path)
    if kind == 'absent':
        return None
    if kind == 'refused' or data is None:
        return 'software update state could not be read'
    try:
        root = plistlib.loads(data)
    except (ValueError, TypeError, plistlib.InvalidFileException):
        return 'software update state is unreadable'
    if not isinstance(root, dict):
        return 'software update state is unreadable'
    fields = root.get('SUCorePersistedStatePolicyFields')
    if not isinstance(fields, dict):
        fields = {}
        root['SUCorePersistedStatePolicyFields'] = fields
    changed = False
    if declarations:
        current = fields.get('Declarations')
        if not isinstance(current, dict):
            current = {}
            fields['Declarations'] = current
        for key, value in declarations.items():
            if key not in current and isinstance(value, dict):
                current[key] = copy.deepcopy(value)
                changed = True
    if settings:
        current_settings = fields.get('SUCoreDDMDeclarationGlobalSettings')
        if not isinstance(current_settings, dict):
            current_settings = {}
            fields['SUCoreDDMDeclarationGlobalSettings'] = current_settings
        for key, value in settings.items():
            if key not in current_settings:
                current_settings[key] = copy.deepcopy(value)
                changed = True
    if not changed:
        return None
    try:
        mode = stat.S_IMODE(info.st_mode) if info is not None else int(slot.get('mode') or 0o644)
        uid = info.st_uid if info is not None else slot.get('uid')
        gid = info.st_gid if info is not None else slot.get('gid')
        _write_bytes(path, plistlib.dumps(root, fmt=plistlib.FMT_BINARY), mode, uid, gid)
    except OSError as error:
        return str(error)
    return None


def public_status(shields, record, network_mode='off', management_ready=False):
    """Status for the activity feed. No file bytes, paths, or URLs."""
    shields = shields or {}
    record = record if isinstance(record, dict) else {}
    del management_ready, network_mode
    tiles = {}
    if shields.get('ddm-update'):
        tiles['ddm-update'] = record.get('softwareupdate_status') or 'restricted'
    elif record.get('softwareupdate_status') == 'reverted':
        tiles['ddm-update'] = 'reverted'
    if shields.get('ddm-installs'):
        tiles['ddm-installs'] = 'partial'
    if shields.get('ddm-assets'):
        tiles['ddm-assets'] = 'partial'
    types = [item for item in record.get('types') or [] if isinstance(item, str) and TYPE_RE.fullmatch(item)]
    return {'tiles': tiles, 'types': types[:12]}
