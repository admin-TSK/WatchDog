import importlib.util, json, os, signal, stat, subprocess, tempfile, time
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('guard', ROOT / 'src' / 'guard.py')
guard = importlib.util.module_from_spec(spec)
spec.loader.exec_module(guard)

def alive(pid):
    r = subprocess.run(['/bin/ps', '-p', str(pid), '-o', 'stat='], capture_output=True, text=True)
    return r.returncode == 0 and r.stdout.strip() and not r.stdout.strip().startswith('Z')

with tempfile.TemporaryDirectory(prefix='watchdog-test-') as tmp:
    temp = Path(tmp).resolve()
    guard.STATE = temp / 'state.json'
    binary = temp / 'permission-fixture'
    binary.write_text('fixture')
    binary.chmod(0o755)
    state = guard.load_state()
    assert not guard.block_modes(state, [binary])
    assert stat.S_IMODE(binary.stat().st_mode) == 0o644
    assert guard.load_state()['modes'][str(binary)] == 0o755
    binary.chmod(0o555)  # Simulated updater restoring execution rights.
    assert not guard.block_modes(state, [binary])
    assert stat.S_IMODE(binary.stat().st_mode) == 0o444
    assert not guard.restore_modes(state)
    assert stat.S_IMODE(binary.stat().st_mode) == 0o755
    print('PASS: execution blocked, replacement permissions blocked, original mode restored.')

    assert Path('/usr/local/bin/jamf') in guard.BASE_EXECUTABLES
    bundle = temp / 'JAMF'
    helper = bundle / 'bin' / 'jamfHelper.app' / 'Contents' / 'MacOS' / 'jamfHelper'
    helper.parent.mkdir(parents=True)
    helper.write_text('helper')
    helper.chmod(0o755)
    note = bundle / 'logs' / 'note.txt'
    note.parent.mkdir()
    note.write_text('data')
    note.chmod(0o644)
    discovered = guard.targets.executables(roots=[bundle])
    assert helper in discovered
    assert note not in discovered
    print('PASS: whole JAMF tree executable discovery; data files skipped.')

    sticky = temp / 'sticky-fixture'
    sticky.write_text('sticky')
    sticky.chmod(0o755)
    sticky_state = {'version': 1, 'modes': {}, 'jobs': {}, 'flags': {}}
    assert not guard.block_modes(sticky_state, [sticky], sticky=True)
    assert stat.S_IMODE(sticky.stat().st_mode) == 0o644
    assert sticky.stat().st_flags & guard.UF_IMMUTABLE
    os.chflags(sticky, 0)
    sticky.chmod(0o755)
    assert not guard.block_modes(sticky_state, [sticky], sticky=True)
    assert sticky.stat().st_flags & guard.UF_IMMUTABLE
    assert not guard.restore_modes(sticky_state)
    assert not (sticky.stat().st_flags & guard.UF_IMMUTABLE)
    assert stat.S_IMODE(sticky.stat().st_mode) == 0o755
    print('PASS: sticky UF_IMMUTABLE set before restore and cleared on restore.')

    migrated = temp / 'v1-fixture'
    migrated.write_text('v1')
    migrated.chmod(0o644)
    v1_path = temp / 'v1-state.json'
    v1_path.write_text(json.dumps({'version': 1, 'modes': {str(migrated): 0o755}, 'jobs': {}}))
    previous = guard.STATE
    guard.STATE = v1_path
    loaded = guard.load_state()
    assert loaded['version'] == 2
    assert loaded['flags'] == {}
    assert loaded['modes'][str(migrated)] == 0o755
    assert not guard.restore_modes(loaded)
    assert stat.S_IMODE(migrated.stat().st_mode) == 0o755
    guard.STATE = previous
    print('PASS: v1 undo record loads as v2 and restores modes without flags.')

    calls = []
    enabled = {'system/com.jamfsoftware.task.1': True, 'system/com.jamf.management.daemon': False}
    loaded = {'system/com.jamfsoftware.task.1'}
    guard.jobs = lambda: {('system', 'com.jamfsoftware.task.1'): ('/test/task.plist', False),
                          ('system', 'com.jamf.management.daemon'): (None, False)}
    def command(*args):
        calls.append(args)
        operation, target = args[1:3]
        output, status = '', 0
        if operation == 'print-disabled':
            output = '\n'.join(f'"{key.split("/")[-1]}" => {"enabled" if value else "disabled"}' for key, value in enabled.items())
        elif operation == 'print': status = 0 if target in loaded else 1
        elif operation == 'disable': enabled[target] = False
        elif operation == 'enable': enabled[target] = True
        elif operation == 'bootout': loaded.discard(target)
        else: raise AssertionError(args)
        return subprocess.CompletedProcess(args, status, output, '')
    guard.command = command
    assert not guard.block_jobs(state)
    assert not any(enabled.values()) and not loaded
    assert state['jobs']['system/com.jamfsoftware.task.1']['disabled'] is False
    assert state['jobs']['system/com.jamf.management.daemon']['disabled'] is True
    # No bootstrap is attempted because the fixture plist does not exist.
    assert not guard.restore(state)
    assert enabled['system/com.jamfsoftware.task.1'] is True
    assert enabled['system/com.jamf.management.daemon'] is False
    print('PASS: launch-job state saved before blocking and original effective states restored (mock launchctl).')

    source = temp / 'fixture.c'
    source.write_text('''#include <unistd.h>
#include <stdio.h>
int main(void) {
    pid_t child = fork();
    if (child == 0) { execl("/bin/sleep", "sleep", "60", (char *)0); _exit(1); }
    printf("%d\\n", child);
    fflush(stdout);
    for (;;) pause();
}
''')
    fixture = temp / 'jamf-fixture'
    subprocess.run(['xcrun', 'clang', str(source), '-o', str(fixture)], check=True)
    # Stay in the test runner's process group so a naive "kill everyone with the
    # same pgid" bug would take down this Python process and the keeper.
    keeper = subprocess.Popen(['/bin/sleep', '60'])
    parent = subprocess.Popen([str(fixture)], stdout=subprocess.PIPE, text=True)
    child = int(parent.stdout.readline().strip())
    time.sleep(0.1)
    watcher = None
    try:
        assert alive(child) and alive(parent.pid)
        started = time.monotonic()
        watcher = subprocess.Popen([str(ROOT / 'build' / 'watchdog'), '--test-target', str(fixture)],
                                   stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True,
                                   start_new_session=True)
        assert parent.wait(timeout=3) == -signal.SIGKILL
        deadline = time.monotonic() + 3
        while alive(child) and time.monotonic() < deadline: time.sleep(0.02)
        assert not alive(child), 'Observed descendant survived'
        assert keeper.poll() is None, 'Unrelated process was killed'
        print(f'PASS: target and observed child killed; unrelated process survived ({time.monotonic()-started:.3f}s).')
        for _ in range(3):
            target = subprocess.Popen([str(fixture)], stdout=subprocess.DEVNULL)
            assert target.wait(timeout=3) == -signal.SIGKILL
        watcher.terminate()
        assert watcher.wait(timeout=3) == 0
        print('PASS: repeated target launches killed; watchdog shuts down cleanly.')
    finally:
        for process in [watcher, parent, keeper]:
            if process and process.poll() is None:
                process.kill(); process.wait()
        if alive(child): os.kill(child, signal.SIGKILL)

    pgid_source = temp / 'pgid.c'
    pgid_source.write_text('''#include <unistd.h>
#include <stdio.h>
#include <sys/wait.h>
int main(void) {
    if (setpgid(0, 0) != 0) return 1;
    pid_t child = fork();
    if (child == 0) {
        pid_t gc = fork();
        if (gc == 0) { for (;;) pause(); }
        printf("%d\\n", gc);
        fflush(stdout);
        _exit(0);
    }
    int st;
    waitpid(child, &st, 0);
    for (;;) pause();
}
''')
    pgid_fixture = temp / 'pgid-fixture'
    subprocess.run(['xcrun', 'clang', str(pgid_source), '-o', str(pgid_fixture)], check=True)
    keeper = subprocess.Popen(['/bin/sleep', '60'])
    parent = subprocess.Popen([str(pgid_fixture)], stdout=subprocess.PIPE, text=True)
    grandchild = int(parent.stdout.readline().strip())
    time.sleep(0.1)
    watcher = None
    try:
        assert alive(grandchild) and alive(parent.pid)
        watcher = subprocess.Popen(
            [str(ROOT / 'build' / 'watchdog'), '--test-target', str(pgid_fixture), '--interval-ms', '20'],
            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True, start_new_session=True)
        assert parent.wait(timeout=3) == -signal.SIGKILL
        deadline = time.monotonic() + 3
        while alive(grandchild) and time.monotonic() < deadline: time.sleep(0.02)
        assert not alive(grandchild), 'Reparented process-group descendant survived'
        assert keeper.poll() is None, 'Unrelated process was killed'
        print('PASS: reparented process-group descendant killed; unrelated process survived.')
        watcher.terminate()
        watcher.wait(timeout=3)
    finally:
        for process in [watcher, parent, keeper]:
            if process and process.poll() is None:
                process.kill(); process.wait()
        if alive(grandchild): os.kill(grandchild, signal.SIGKILL)
print('All isolated checks passed. No real Jamf processes or management settings were changed.')
