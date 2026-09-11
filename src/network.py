"""Outbound PF rules for WatchDog's Network shield (Off / On / Yeet).

The guard calls sync/flush. Tests inject run/resolve/discover and never enable live PF.
Empty host lists never mean all hosts. Direction is outbound only.
"""
import ipaddress
import json
import os
import plistlib
import re
import socket
import subprocess
from pathlib import Path
from urllib.parse import urlparse

MODES = ('off', 'on', 'yeet')
ANCHOR = 'local.watchdog'
PFCTL = '/sbin/pfctl'
PF_CONF = Path('/etc/pf.conf')
JAMF_PLIST = Path('/Library/Preferences/com.jamfsoftware.jamf.plist')
MARKER_BEGIN = '# BEGIN local.watchdog'
MARKER_END = '# END local.watchdog'
MARKER_RE = re.compile(
    r'\n?' + re.escape(MARKER_BEGIN) + r'\n.*?' + re.escape(MARKER_END) + r'\n?',
    re.DOTALL,
)
ENABLE_TOKEN_RE = re.compile(r'(?im)^\s*Token\s*:\s*(\d+)\s*$')
YEET_WARNING = (
    'WARNING: Network Yeet blocks Apple Push (TCP 5223 and 443 to published APNs '
    'ranges). iMessage and other push services will break. Enrollment stays. VPN or '
    'a proxy can bypass this filter. Uninstall or set Network Off to remove only '
    'WatchDog’s PF anchor.'
)
ACTIONS = {'deny'}
TRANSPORTS = {'tcp'}
DIRECTIONS = {'out'}
PROFILES = '/usr/bin/profiles'
STATE_KILL_CAP = 8
STATE_KILL_TIMEOUT = 2
STATE_KILL_STOP_AFTER = 2
MGMT_KILL_WARNING = 'Existing Jamf connections were not reset'


def normalize_host(value):
    if not isinstance(value, str):
        return ''
    return value.strip().rstrip('.').lower()


def host_from_url(value):
    endpoint = endpoint_from_url(value)
    return endpoint[0] if endpoint else None


def endpoint_from_url(value):
    """Return (host, port). Host only; no path or query. Port defaults to 443."""
    if not value or not isinstance(value, str):
        return None
    text = value.strip().strip('"')
    if '://' not in text:
        text = 'https://' + text
    parsed = urlparse(text)
    host = normalize_host(parsed.hostname or '')
    if not host:
        return None
    try:
        port = int(parsed.port) if parsed.port is not None else 443
    except (TypeError, ValueError):
        port = 443
    if port < 1 or port > 65535:
        port = 443
    return host, port


def wildcard_matches(pattern, name):
    pattern = normalize_host(pattern)
    name = normalize_host(name)
    if not pattern.startswith('*.'):
        return pattern == name
    suffix = pattern[1:]
    parent = pattern[2:]
    if not name or name == parent:
        return False
    return name.endswith(suffix) and name[: -len(suffix)].rstrip('.') != ''


def parse_cidr(value):
    network = ipaddress.ip_network(value, strict=False)
    return str(network)


def load_policy(path):
    data = json.loads(Path(path).read_text())
    if not isinstance(data, dict) or data.get('schema') != 1:
        raise ValueError('network policy schema must be 1')
    groups = data.get('groups')
    if not isinstance(groups, list) or not groups:
        raise ValueError('network policy needs groups')
    parsed = []
    for group in groups:
        parsed.append(_parse_group(group))
    return {'schema': 1, 'groups': parsed}


def _parse_group(group):
    if not isinstance(group, dict):
        raise ValueError('group must be an object')
    identity = group.get('id')
    if not isinstance(identity, str) or not identity:
        raise ValueError('group id required')
    modes = tuple(group.get('modes') or ())
    if any(mode not in {'on', 'yeet'} for mode in modes):
        raise ValueError(f'{identity}: unknown mode')
    direction = group.get('direction', 'out')
    transport = group.get('transport', 'tcp')
    action = group.get('action', 'deny')
    if direction not in DIRECTIONS:
        raise ValueError(f'{identity}: inbound rules are not supported')
    if transport not in TRANSPORTS or action not in ACTIONS:
        raise ValueError(f'{identity}: unknown action or transport')
    ports = tuple(int(port) for port in group.get('ports') or ())
    if not ports:
        raise ValueError(f'{identity}: ports required')
    hosts = [normalize_host(host) for host in group.get('hosts') or [] if normalize_host(host)]
    cidrs = [parse_cidr(item) for item in group.get('cidrs') or []]
    discover = group.get('discover')
    if discover not in (None, 'management'):
        raise ValueError(f'{identity}: unknown discover')
    if not hosts and not cidrs and discover is None:
        raise ValueError(f'{identity}: empty destination list is not all hosts')
    return {
        'id': identity,
        'modes': modes,
        'direction': direction,
        'transport': transport,
        'ports': ports,
        'hosts': hosts,
        'cidrs': cidrs,
        'discover': discover,
    }


def groups_for_mode(policy, mode):
    if mode not in ('on', 'yeet'):
        return []
    return [group for group in policy['groups'] if mode in group['modes']]


def discover_management_endpoints(jamf_plist=None, enrollment_text=None):
    """Return (host, port) pairs. Never keep URL paths or query strings."""
    found = []
    path = Path(jamf_plist) if jamf_plist is not None else JAMF_PLIST
    try:
        with open(path, 'rb') as stream:
            data = plistlib.load(stream)
        if isinstance(data, dict):
            for key in ('jss_url', 'url', 'jss_url_raw'):
                endpoint = endpoint_from_url(data.get(key))
                if endpoint:
                    found.append(endpoint)
    except (OSError, ValueError, plistlib.InvalidFileException):
        pass
    text = enrollment_text or ''
    for match in re.finditer(
            r'(?:MDM server|ServerURL|CheckInURL)[:\s=]+([^\s]+)', text, re.I):
        endpoint = endpoint_from_url(match.group(1).strip().strip('",'))
        if endpoint:
            found.append(endpoint)
    unique = []
    seen = set()
    for host, port in found:
        key = (host, port)
        if key in seen:
            continue
        seen.add(key)
        unique.append((host, port))
    return unique


def discover_management_hosts(jamf_plist=None, enrollment_text=None):
    """Return hostnames only. Never keep URL paths or query strings."""
    hosts = []
    for host, _port in discover_management_endpoints(
            jamf_plist=jamf_plist, enrollment_text=enrollment_text):
        if host not in hosts:
            hosts.append(host)
    return hosts


def enrollment_text_from_profiles(run=None, timeout=3):
    """Read local enrollment display text. Caller must not log the raw URL."""
    run = run or _subprocess_run
    result = _run(run, [PROFILES, 'show', '-type', 'enrollment'], timeout=timeout)
    if result.returncode:
        return ''
    return result.stdout or ''


def resolve_host(host, getaddrinfo=socket.getaddrinfo):
    v4, v6 = set(), set()
    try:
        records = getaddrinfo(host, 443, type=socket.SOCK_STREAM)
    except (OSError, socket.gaierror):
        return v4, v6
    for family, _type, _proto, _canon, sockaddr in records:
        if family == socket.AF_INET and sockaddr:
            v4.add(sockaddr[0])
        elif family == socket.AF_INET6 and sockaddr:
            v6.add(sockaddr[0].split('%')[0])
    return v4, v6


def collect_destinations(groups, discovered, resolve=resolve_host, endpoints=None):
    """Build PF tables. Wildcards without CIDRs are partial, not expanded."""
    https_v4, https_v6 = set(), set()
    apns_v4, apns_v6 = set(), set()
    mgmt_v4, mgmt_v6 = set(), set()
    mgmt_ports = {443}
    if endpoints:
        for item in endpoints:
            if not item or len(item) < 2:
                continue
            try:
                port = int(item[1])
            except (TypeError, ValueError):
                continue
            if 1 <= port <= 65535:
                mgmt_ports.add(port)
    partial, stale = [], []
    resolved = 0
    for group in groups:
        if group.get('discover') == 'management':
            table_v4, table_v6 = mgmt_v4, mgmt_v6
        elif group['id'] == 'apns':
            table_v4, table_v6 = apns_v4, apns_v6
        else:
            table_v4, table_v6 = https_v4, https_v6
        hosts = list(group['hosts'])
        if group.get('discover') == 'management':
            hosts.extend(discovered)
        for cidr in group['cidrs']:
            network = ipaddress.ip_network(cidr, strict=False)
            if network.version == 4:
                table_v4.add(str(network))
            else:
                table_v6.add(str(network))
        for host in hosts:
            if host.startswith('*.'):
                if not group['cidrs']:
                    partial.append(group['id'])
                continue
            if not host:
                continue
            v4, v6 = resolve(host)
            if not v4 and not v6:
                stale.append(host)
                continue
            table_v4.update(v4)
            table_v6.update(v6)
            resolved += 1
    return {
        'https_v4': sorted(https_v4),
        'https_v6': sorted(https_v6),
        'mgmt_v4': sorted(mgmt_v4),
        'mgmt_v6': sorted(mgmt_v6),
        'mgmt_ports': tuple(sorted(mgmt_ports)) if (mgmt_v4 or mgmt_v6) else (),
        'apns_v4': sorted(apns_v4),
        'apns_v6': sorted(apns_v6),
        'partial': sorted(set(partial)),
        'stale': sorted(set(stale)),
        'resolved_count': resolved,
    }


def _table_block(name, entries, ports):
    if not entries:
        return []
    members = ', '.join(entries)
    ports_text = ', '.join(str(port) for port in ports)
    return [
        f'table <{name}> persist {{ {members} }}',
        f'block drop out proto tcp from any to <{name}> port {{ {ports_text} }}',
    ]


def generate_anchor(mode, destinations):
    if mode not in ('on', 'yeet'):
        return '# WatchDog network off\n'
    lines = [
        f'# WatchDog network {mode} — outbound destination denies only',
    ]
    lines.extend(_table_block('watchdog_https_v4', destinations.get('https_v4') or [], (443,)))
    lines.extend(_table_block('watchdog_https_v6', destinations.get('https_v6') or [], (443,)))
    mgmt_ports = tuple(destinations.get('mgmt_ports') or (443,))
    lines.extend(_table_block('watchdog_mgmt_v4', destinations.get('mgmt_v4') or [], mgmt_ports))
    lines.extend(_table_block('watchdog_mgmt_v6', destinations.get('mgmt_v6') or [], mgmt_ports))
    if mode == 'yeet':
        lines.extend(_table_block('watchdog_apns_v4', destinations.get('apns_v4') or [], (443, 5223)))
        lines.extend(_table_block('watchdog_apns_v6', destinations.get('apns_v6') or [], (443, 5223)))
    text = '\n'.join(lines) + '\n'
    for line in text.splitlines():
        if line.startswith('block ') and ' to ' not in line:
            raise ValueError('refusing a port-only PF rule')
        if line.startswith('block ') and ' out ' not in line:
            raise ValueError('refusing a non-outbound PF rule')
    return text


def read_status(root):
    path = Path(root) / 'network-status.json'
    blank = {
        'mode': 'off',
        'anchor_loaded': False,
        'resolved_count': 0,
        'partial': [],
        'stale': [],
        'pf_enabled': False,
    }
    try:
        data = json.loads(path.read_text())
    except (OSError, ValueError, TypeError):
        return blank
    if not isinstance(data, dict):
        return blank
    blank.update({
        'mode': data['mode'] if data.get('mode') in MODES else 'off',
        'anchor_loaded': bool(data.get('anchor_loaded')),
        'resolved_count': int(data.get('resolved_count') or 0),
        'partial': [item for item in data.get('partial') or [] if isinstance(item, str)],
        'stale': [item for item in data.get('stale') or [] if isinstance(item, str)],
        'pf_enabled': bool(data.get('pf_enabled')),
    })
    return blank


def _write_json(path, payload):
    path = Path(path)
    temporary = path.with_suffix('.tmp')
    with open(temporary, 'w') as stream:
        os.chmod(temporary, 0o600)
        json.dump(payload, stream, indent=2)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)


def _pf_conf_has_marker(text):
    return MARKER_BEGIN in text and MARKER_END in text


def _insert_marker(text, load_path):
    block = (
        f'{MARKER_BEGIN}\n'
        f'anchor "{ANCHOR}"\n'
        f'load anchor "{ANCHOR}" from "{load_path}"\n'
        f'{MARKER_END}\n'
    )
    if _pf_conf_has_marker(text):
        return MARKER_RE.sub('\n' + block, text), False
    prefix = text if text.endswith('\n') or not text else text + '\n'
    return prefix + block, True


def _strip_marker(text):
    return MARKER_RE.sub('\n', text)


def _run(run, args, timeout=10):
    """Run pfctl. Timeouts become a failed result so a stuck -k cannot abort the sync."""
    try:
        return run(args, text=True, capture_output=True, check=False, timeout=timeout)
    except subprocess.TimeoutExpired as error:
        stdout = error.stdout if isinstance(error.stdout, str) else ''
        stderr = error.stderr if isinstance(error.stderr, str) else ''
        return subprocess.CompletedProcess(
            list(args), 124, stdout or '', stderr or f'timed out after {timeout}s')


def _pfctl_message(stderr, fallback):
    text = ' '.join((stderr or '').split())
    if 'option requires an argument -- X' in text:
        return 'Could not release the packet filter enable token because it was missing'
    if text.startswith('pfctl:') and '/' not in text:
        return text
    return fallback


def parse_enable_token(text):
    """Read the reference token printed by pfctl -E. -X requires that token."""
    match = ENABLE_TOKEN_RE.search(text or '')
    return enable_token(match.group(1)) if match else None


def enable_token(value):
    """Return a pfctl -X argument, or None when the value is not a token."""
    if value is None:
        return None
    text = str(value).strip()
    if not text.isascii() or not text.isdigit() or len(text) > 20:
        return None
    return text


REFERENCE_ROW_RE = re.compile(
    r'^\s*\d+\s+(.+?)\s+(\d+)\s+\d+\s+days(?:\s+\d{2}:\d{2}:\d{2})?\s*$',
    re.IGNORECASE,
)


def _is_watchdog_enabler(name):
    """True only for WatchDog’s own process names. Never Apple watchdogd."""
    lowered = name.lower().replace('\\', '/')
    if 'watchdogd' in lowered:
        return False
    basename = Path(name).name.lower()
    if basename in {'run-guard', 'guard.py'}:
        return True
    return 'run-guard' in lowered or 'guard.py' in lowered or '/watchdog/guard.py' in lowered


def tokens_from_references(text):
    """Parse pfctl -s References. Only release tokens whose process is WatchDog."""
    tokens = []
    for line in (text or '').splitlines():
        stripped = line.strip()
        if not stripped or stripped.upper().startswith('TOKENS') or stripped.upper().startswith('PID'):
            continue
        match = REFERENCE_ROW_RE.match(stripped)
        if match:
            name, token = match.group(1), match.group(2)
        else:
            parts = stripped.split()
            if len(parts) < 3 or not parts[0].isdigit():
                continue
            name, token = parts[1], parts[2]
        token = enable_token(token)
        if not token or not _is_watchdog_enabler(name):
            continue
        if token not in tokens:
            tokens.append(token)
    return tokens


def _is_unicast(addr):
    if not addr or not isinstance(addr, str) or '/' in addr:
        return False
    try:
        ipaddress.ip_address(addr)
    except ValueError:
        return False
    return True


def _unicast_list(*groups):
    seen = []
    for addr in groups:
        if _is_unicast(addr) and addr not in seen:
            seen.append(addr)
    return seen


def state_kill_targets(destinations):
    """Unicast destinations only, management first, capped. Never CIDRs."""
    destinations = destinations or {}
    management = _unicast_list(
        *(destinations.get('mgmt_v4') or []),
        *(destinations.get('mgmt_v6') or []))
    other = _unicast_list(
        *(destinations.get('https_v4') or []),
        *(destinations.get('https_v6') or []),
        *(destinations.get('apns_v4') or []),
        *(destinations.get('apns_v6') or []))
    ordered = []
    for addr in management + other:
        if addr not in ordered:
            ordered.append(addr)
    return ordered[:STATE_KILL_CAP], set(management)


def _pf_not_enabled(stderr):
    text = (stderr or '').lower()
    return any(needle in text for needle in (
        'device not configured',
        'pf is disabled',
        '/dev/pf: no such file',
        'pfctl: /dev/pf',
    ))


def _anchor_has_rules(run, pfctl, commands):
    show = [pfctl, '-a', ANCHOR, '-s', 'rules']
    commands.append(show)
    result = _run(run, show)
    if result.returncode:
        return False
    for line in (result.stdout or '').splitlines():
        text = line.strip()
        if text and not text.startswith('#'):
            return True
    return False


def _enable_packet_filter(run, pfctl, pf, commands, failures):
    enable = [pfctl, '-E']
    commands.append(enable)
    result = _run(run, enable)
    if result.returncode:
        failures.append(_pfctl_message(result.stderr, 'Could not enable the packet filter'))
        return False
    pf['enabled_incremented'] = True
    token = parse_enable_token(result.stdout) or parse_enable_token(result.stderr)
    if not token:
        failures.append('Packet filter enable did not return a token')
        return False
    pf['enable_token'] = token
    return True


def _kill_unicast_states(run, pfctl, destinations, commands):
    """Best-effort state kill. Timeouts do not fail rule load."""
    warnings = []
    targets, management = state_kill_targets(destinations)
    consecutive = 0
    management_timed_out = False
    for addr in targets:
        source = '::/0' if ':' in addr else '0.0.0.0/0'
        kill = [pfctl, '-k', source, '-k', addr]
        commands.append(kill)
        killed = _run(run, kill, timeout=STATE_KILL_TIMEOUT)
        if killed.returncode == 124:
            consecutive += 1
            if addr in management:
                management_timed_out = True
            if consecutive >= STATE_KILL_STOP_AFTER:
                break
        else:
            consecutive = 0
    if management_timed_out:
        warnings.append(MGMT_KILL_WARNING)
    return warnings


def _pf_is_recorded(root, pf):
    """True when WatchDog previously enabled PF, even if state.json lost the flags.

    Uses only the install directory (undo flags and network-status.json), never
    /etc/pf.conf, so isolated tests cannot see a live marker.
    """
    if pf.get('conf_marked') or pf.get('enabled_incremented') or pf.get('enable_token'):
        return True
    status = read_status(root)
    return bool(status.get('anchor_loaded') or status.get('pf_enabled') or status.get('mode') in ('on', 'yeet'))


def flush(root, state, *, run=None, pf_conf=None, pfctl=PFCTL, force=False):
    """Remove only WatchDog’s anchor and pf.conf marker. Never pfctl -F all.

    Without force, skip PF entirely when this install never recorded a marker or
    enable increment so isolated tests cannot touch /etc/pf.conf.
    """
    run = run or _subprocess_run
    root = Path(root)
    conf_path = Path(pf_conf) if pf_conf is not None else PF_CONF
    commands = []
    failures = []
    pf = state.setdefault('pf', {}) if isinstance(state, dict) else {}
    status = read_status(root)
    if not force and not _pf_is_recorded(root, pf):
        _write_json(root / 'network-status.json', {
            'mode': 'off', 'anchor_loaded': False, 'resolved_count': 0,
            'partial': [], 'stale': [], 'pf_enabled': False,
        })
        return [], []

    flush_cmd = [pfctl, '-a', ANCHOR, '-F', 'all']
    commands.append(flush_cmd)
    result = _run(run, flush_cmd)
    if result.returncode:
        failures.append(_pfctl_message(result.stderr, 'Could not flush the WatchDog packet-filter anchor'))

    if pf.get('conf_marked') or (conf_path.exists() and MARKER_BEGIN in conf_path.read_text()):
        original = conf_path.read_text() if conf_path.exists() else ''
        updated = _strip_marker(original)
        if updated != original:
            conf_path.write_text(updated)
            reload_cmd = [pfctl, '-f', str(conf_path)]
            commands.append(reload_cmd)
            result = _run(run, reload_cmd)
            if result.returncode:
                failures.append(_pfctl_message(result.stderr, 'Could not reload pf.conf after marker removal'))
        pf['conf_marked'] = False

    tokens = []
    stored = enable_token(pf.get('enable_token'))
    if stored:
        tokens.append(stored)
    if not tokens and (pf.get('enabled_incremented') or status.get('pf_enabled')):
        listed = [pfctl, '-s', 'References']
        commands.append(listed)
        result = _run(run, listed)
        tokens.extend(tokens_from_references(result.stdout or result.stderr))
    released = False
    for token in tokens:
        xref = [pfctl, '-X', token]
        commands.append(xref)
        result = _run(run, xref)
        if result.returncode:
            failures.append(_pfctl_message(result.stderr, 'Could not release the packet filter enable token'))
        else:
            released = True
    if released or tokens:
        pf['enabled_incremented'] = False
        pf['enable_token'] = None
    elif pf.get('enabled_incremented') or status.get('pf_enabled'):
        failures.append('Could not release the packet filter enable token because it was not recorded')
        pf['enabled_incremented'] = False
        pf['enable_token'] = None

    for name in ('pf.anchor',):
        try:
            (root / name).unlink()
        except FileNotFoundError:
            pass
    _write_json(root / 'network-status.json', {
        'mode': 'off', 'anchor_loaded': False, 'resolved_count': 0,
        'partial': [], 'stale': [], 'pf_enabled': False,
    })
    return failures, commands


def sync(mode, root, state, *, run=None, resolve=None, discover=None, pf_conf=None,
         pfctl=PFCTL, policy_path=None, enrollment_text=None, kill_states=True):
    """Install or refresh the WatchDog PF anchor. mode is off, on, or yeet."""
    run = run or _subprocess_run
    resolve = resolve or resolve_host
    root = Path(root)
    if mode not in MODES:
        mode = 'off'
    if mode == 'off':
        return flush(root, state, run=run, pf_conf=pf_conf, pfctl=pfctl)

    policy = load_policy(policy_path or root / 'network_policy.json')
    groups = groups_for_mode(policy, mode)
    if discover:
        discovered = list(discover())
        endpoints = [(host, 443) for host in discovered]
    else:
        text = enrollment_text
        if text is None:
            text = enrollment_text_from_profiles(run)
        endpoints = discover_management_endpoints(enrollment_text=text)
        discovered = []
        for host, _port in endpoints:
            if host not in discovered:
                discovered.append(host)
    destinations = collect_destinations(
        groups, discovered, resolve=resolve, endpoints=endpoints)
    anchor = generate_anchor(mode, destinations)
    anchor_path = root / 'pf.anchor'
    anchor_path.write_text(anchor)
    os.chmod(anchor_path, 0o600)

    conf_path = Path(pf_conf) if pf_conf is not None else PF_CONF
    pf = state.setdefault('pf', {}) if isinstance(state, dict) else {}
    commands = []
    failures = []

    current = conf_path.read_text() if conf_path.exists() else ''
    updated, _inserted = _insert_marker(current, str(anchor_path))
    reload_needed = updated != current
    if updated != current:
        conf_path.write_text(updated)
        pf['conf_marked'] = True
    elif _pf_conf_has_marker(updated):
        pf['conf_marked'] = True
        reload_needed = not _anchor_has_rules(run, pfctl, commands)
    if reload_needed:
        reload_cmd = [pfctl, '-f', str(conf_path)]
        commands.append(reload_cmd)
        result = _run(run, reload_cmd)
        if result.returncode:
            failures.append(result.stderr.strip() or 'Could not load pf.conf with WatchDog anchor')

    if not pf.get('enable_token') and not pf.get('enabled_incremented'):
        _enable_packet_filter(run, pfctl, pf, commands, failures)

    load_anchor = [pfctl, '-a', ANCHOR, '-f', str(anchor_path)]
    commands.append(load_anchor)
    result = _run(run, load_anchor)
    if result.returncode and _pf_not_enabled(result.stderr):
        if _enable_packet_filter(run, pfctl, pf, commands, failures):
            commands.append(load_anchor)
            result = _run(run, load_anchor)
    if result.returncode:
        failures.append(_pfctl_message(result.stderr, 'Could not load WatchDog PF anchor'))

    warnings = []
    if kill_states:
        warnings.extend(_kill_unicast_states(run, pfctl, destinations, commands))

    status = {
        'mode': mode,
        'anchor_loaded': not bool(failures),
        'resolved_count': destinations['resolved_count'],
        'partial': destinations['partial'],
        'stale': destinations['stale'],
        'pf_enabled': bool(pf.get('enable_token') or pf.get('enabled_incremented')),
    }
    _write_json(root / 'network-status.json', status)
    return failures + warnings, commands


def _subprocess_run(args, **kwargs):
    return subprocess.run(args, **kwargs)
