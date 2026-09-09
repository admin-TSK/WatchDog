#include <libproc.h>
#include <sys/proc_info.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>

static volatile sig_atomic_t running = 1;
static const char *test_target = NULL;
static void stop(int sig) { (void)sig; running = 0; }
typedef struct { pid_t pid, ppid; uint64_t sec, usec; int selected; } Entry;
static int target_path(const char *path) {
    if (test_target) return strcmp(path, test_target) == 0;
    const char *prefix = "/System/Volumes/Data";
    if (strncmp(path, prefix, strlen(prefix)) == 0) path += strlen(prefix);
    const char *bundle = "/Library/Application Support/JAMF/Jamf.app/";
    return strcmp(path, "/usr/local/jamf/bin/jamf") == 0 ||
           strcmp(path, "/usr/local/bin/jamf") == 0 ||
           strcmp(path, "/usr/local/jamf/bin/jamfAgent") == 0 ||
           strncasecmp(path, bundle, strlen(bundle)) == 0;
}
static int same_process(Entry *entry) {
    struct proc_bsdinfo info;
    int n = proc_pidinfo(entry->pid, PROC_PIDTBSDINFO, 0, &info, sizeof(info));
    return n == sizeof(info) && info.pbi_start_tvsec == entry->sec && info.pbi_start_tvusec == entry->usec;
}
static int snapshot(Entry **entries) {
    int capacity = proc_listallpids(NULL, 0) + 512;
    if (capacity < 512) capacity = 512;
    pid_t *pids = NULL;
    int count;
    for (;;) {
        pid_t *next = realloc(pids, (size_t)capacity * sizeof(pid_t));
        if (!next) { free(pids); return -1; }
        pids = next;
        count = proc_listallpids(pids, capacity * (int)sizeof(pid_t));
        if (count < capacity) break;
        capacity *= 2;
    }
    if (count <= 0) { free(pids); return -1; }
    Entry *out = calloc((size_t)count, sizeof(Entry));
    if (!out) { free(pids); return -1; }
    int used = 0;
    for (int i = 0; i < count; i++) {
        if (pids[i] <= 1 || pids[i] == getpid()) continue;
        struct proc_bsdinfo info;
        if (proc_pidinfo(pids[i], PROC_PIDTBSDINFO, 0, &info, sizeof(info)) != sizeof(info)) continue;
        char path[PROC_PIDPATHINFO_MAXSIZE] = {0};
        int selected = proc_pidpath(pids[i], path, sizeof(path)) > 0 && target_path(path);
        out[used++] = (Entry){pids[i], (pid_t)info.pbi_ppid, info.pbi_start_tvsec, info.pbi_start_tvusec, selected};
    }
    free(pids);
    *entries = out;
    return used;
}
int main(int argc, char **argv) {
    if (argc == 3 && strcmp(argv[1], "--test-target") == 0 && argv[2][0] == '/') {
        test_target = argv[2];
    } else if (argc != 1 || geteuid() != 0) {
        fprintf(stderr, "Run installed WatchDog monitor as root, or use --test-target /absolute/test/executable.\n");
        return 2;
    }
    signal(SIGTERM, stop);
    signal(SIGINT, stop);
    setvbuf(stderr, NULL, _IOLBF, 0);
    fprintf(stderr, "WatchDog monitor started; 100 ms polling; mode=%s.\n", test_target ? "isolated test" : "Jamf Pro framework");
    while (running) {
        Entry *entries = NULL;
        int count = snapshot(&entries), found = 0;
        if (count < 0) { fprintf(stderr, "Process enumeration failed.\n"); return 1; }
        /* Pause matching parents before obtaining a fresh descendant snapshot. */
        for (int i = 0; i < count; i++) {
            if (entries[i].selected && same_process(&entries[i])) {
                if (kill(entries[i].pid, SIGSTOP) == 0) found = 1;
                else if (errno != ESRCH) fprintf(stderr, "Cannot pause PID %d: %s\n", entries[i].pid, strerror(errno));
            }
        }
        if (found) {
            Entry *fresh = NULL;
            int fresh_count = snapshot(&fresh);
            if (fresh_count >= 0) {
                /* Keep stable identities of every root we paused, even if a
                   later path lookup fails. This avoids leaving it suspended. */
                Entry *combined = realloc(fresh, (size_t)(fresh_count + count) * sizeof(Entry));
                if (combined) {
                    fresh = combined;
                    for (int i = 0; i < count; i++) {
                        if (!entries[i].selected) continue;
                        int present = 0;
                        for (int j = 0; j < fresh_count; j++) {
                            if (fresh[j].pid == entries[i].pid && fresh[j].sec == entries[i].sec && fresh[j].usec == entries[i].usec) {
                                fresh[j].selected = 1; present = 1; break;
                            }
                        }
                        if (!present) fresh[fresh_count++] = entries[i];
                    }
                    free(entries); entries = fresh; count = fresh_count;
                } else free(fresh);
            }
            int changed;
            do {
                changed = 0;
                for (int i = 0; i < count; i++) {
                    if (entries[i].selected) continue;
                    for (int j = 0; j < count; j++) {
                        if (entries[j].selected && entries[i].ppid == entries[j].pid) {
                            entries[i].selected = 1;
                            changed = 1;
                            break;
                        }
                    }
                }
            } while (changed);
            for (int i = 0; i < count; i++)
                if (entries[i].selected && same_process(&entries[i])) (void)kill(entries[i].pid, SIGSTOP);
            /* Always finish cleanup even if a stop request arrives mid-pass. */
            for (int i = count - 1; i >= 0; i--) {
                if (!entries[i].selected || !same_process(&entries[i])) continue;
                if (kill(entries[i].pid, SIGKILL) == 0)
                    fprintf(stderr, "Killed framework process or observed descendant PID %d.\n", entries[i].pid);
                else if (errno != ESRCH) {
                    fprintf(stderr, "Cannot kill PID %d: %s\n", entries[i].pid, strerror(errno));
                    (void)kill(entries[i].pid, SIGCONT);
                }
            }
        }
        free(entries);
        struct timespec delay = { .tv_sec = 0, .tv_nsec = 100000000L };
        while (running && nanosleep(&delay, &delay) == -1 && errno == EINTR) {}
    }
    fprintf(stderr, "WatchDog monitor stopped.\n");
    return 0;
}
