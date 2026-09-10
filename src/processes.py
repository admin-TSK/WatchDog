"""Read macOS process metadata without spawning the system-wide ps command."""
import ctypes as C
import errno
import os


class ShortInfo(C.Structure):
    _fields_ = [(name, C.c_uint32) for name in ('pid', 'ppid', 'pgid', 'status')] + [
        ('comm', C.c_char * 16)] + [(name, C.c_uint32) for name in
        ('flags', 'uid', 'gid', 'ruid', 'rgid', 'svuid', 'svgid', 'reserved')]


lib = C.CDLL('/usr/lib/libproc.dylib', use_errno=True)
lib.proc_listpids.argtypes = [C.c_uint32, C.c_uint32, C.c_void_p, C.c_int]
lib.proc_listpids.restype = C.c_int
lib.proc_pidinfo.argtypes = [C.c_int, C.c_int, C.c_uint64, C.c_void_p, C.c_int]
lib.proc_pidinfo.restype = C.c_int
lib.proc_pidpath.argtypes = [C.c_int, C.c_void_p, C.c_uint32]
lib.proc_pidpath.restype = C.c_int


def pids(parent=None):
    kind, value = (1, 0) if parent is None else (6, parent)
    size = lib.proc_listpids(kind, value, None, 0)
    if size <= 0:
        raise OSError(C.get_errno(), 'Cannot enumerate processes')
    for _ in range(4):
        buffer = (C.c_int * (size // C.sizeof(C.c_int) + 256))()
        C.set_errno(0)
        used = lib.proc_listpids(kind, value, buffer, C.sizeof(buffer))
        if used < 0 or (used == 0 and C.get_errno()):
            raise OSError(C.get_errno(), 'Cannot enumerate processes')
        if used < C.sizeof(buffer):
            return [pid for pid in buffer[:used // C.sizeof(C.c_int)] if pid > 0]
        size = C.sizeof(buffer) * 2
    raise RuntimeError('Process list kept growing during enumeration')


def info(pid):
    result = ShortInfo()
    count = lib.proc_pidinfo(pid, 13, 0, C.byref(result), C.sizeof(result))
    if count == C.sizeof(result):
        return result
    error = C.get_errno()
    if error in (errno.ESRCH, errno.ENOENT):
        return None  # Normal race with a process exiting.
    raise OSError(error, 'Cannot read process metadata')


def path(pid):
    buffer = C.create_string_buffer(4096)
    count = lib.proc_pidpath(pid, buffer, len(buffer))
    return os.fsdecode(buffer.value) if count > 0 else None


def login_uids():
    result = {os.stat('/dev/console').st_uid}
    for pid in pids():
        process = info(pid)
        if process and process.comm == b'loginwindow':
            result.add(process.uid)
    return result


def has_child(parent, paths):
    return any(path(pid) in paths for pid in pids(parent))
