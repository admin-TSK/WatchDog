#include <libproc.h>
#include <sys/proc_info.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>

static volatile sig_atomic_t running = 1;
static const char *test_target = NULL;
static int match_signature = 0;
static int block_connect = 0;
static long interval_ns = 50000000L; /* 50 ms default */
static void stop(int sig) { (void)sig; running = 0; }
typedef struct { pid_t pid, ppid, pgid; uint64_t sec, usec; int selected; } Entry;

static int has_prefix(const char *path, const char *prefix) {
    size_t n = strlen(prefix);
    return strncmp(path, prefix, n) == 0;
}

static int excluded_path(const char *path) {
    /* WATCHDOG_TARGETS_EXCLUDE */
    static const char *exclude[] = {
        "/Applications/jamfcheck.app/",
        "/Applications/Jamf Compliance Editor.app/",
        "/Library/Application Support/JamfProtect/",
        "/Library/Management/AppAutoPatch/",
        "/Library/Application Support/WatchDog/",
        "/Library/Application Support/Jamf Test Blocker/",
        "/Library/Security/SecurityAgentPlugins/",
        NULL
    };
    /* WATCHDOG_TARGETS_EXCLUDE_END */
    for (int i = 0; exclude[i]; i++)
        if (has_prefix(path, exclude[i]) || strcmp(path, exclude[i]) == 0) return 1;
    return 0;
}

static int identifier_allowed(const char *ident) {
    if (!ident || !ident[0]) return 0;
    /* WATCHDOG_TARGETS_SIGNATURE_DENY */
    static const char *deny[] = {
        "com.jamf.protect",
        "com.jamf.complianceeditor",
        "com.txhaflaire",
        NULL
    };
    /* WATCHDOG_TARGETS_SIGNATURE_DENY_END */
    for (int i = 0; deny[i]; i++)
        if (strcmp(ident, deny[i]) == 0 || strncmp(ident, deny[i], strlen(deny[i])) == 0) return 0;
    /* WATCHDOG_TARGETS_SIGNATURE_ALLOW */
    static const char *allow[] = {
        "com.jamfsoftware.",
        "com.jamf.management.",
        "com.jamf.appinstallers.",
        "com.jamf.selfservice",
        NULL
    };
    /* WATCHDOG_TARGETS_SIGNATURE_ALLOW_END */
    for (int i = 0; allow[i]; i++) {
        size_t n = strlen(allow[i]);
        if (strncmp(ident, allow[i], n) == 0) return 1;
        if (allow[i][n - 1] == '.' && n > 1 && strncmp(ident, allow[i], n - 1) == 0 && ident[n - 1] == 0) return 1;
    }
    if (block_connect) {
        /* WATCHDOG_TARGETS_SIGNATURE_CONNECT */
        static const char *connect[] = {
            "com.jamf.connect.",
            "com.jamf.connect",
            NULL
        };
        /* WATCHDOG_TARGETS_SIGNATURE_CONNECT_END */
        for (int i = 0; connect[i]; i++) {
            size_t n = strlen(connect[i]);
            if (strcmp(ident, connect[i]) == 0 || strncmp(ident, connect[i], n) == 0) return 1;
        }
    }
    return 0;
}

static int path_matches(const char *path) {
    /* WATCHDOG_TARGETS_EXACT */
    static const char *exact[] = {
        "/usr/local/jamf/bin/jamf",
        "/usr/local/bin/jamf",
        "/usr/local/jamf/bin/jamfAgent",
        NULL
    };
    /* WATCHDOG_TARGETS_EXACT_END */
    /* WATCHDOG_TARGETS_PREFIX */
    static const char *prefixes[] = {
        "/Library/Application Support/JAMF/",
        "/Library/Application Support/JamfAppInstallers/",
        "/Applications/Self Service.app/",
        "/Applications/Jamf Self Service.app/",
        NULL
    };
    /* WATCHDOG_TARGETS_PREFIX_END */
    for (int i = 0; exact[i]; i++)
        if (strcmp(path, exact[i]) == 0) return 1;
    for (int i = 0; prefixes[i]; i++)
        if (has_prefix(path, prefixes[i])) return 1;
    if (block_connect) {
        /* WATCHDOG_TARGETS_CONNECT_EXACT */
        static const char *connect_exact[] = {
            "/usr/local/bin/authchanger",
            NULL
        };
        /* WATCHDOG_TARGETS_CONNECT_EXACT_END */
        /* WATCHDOG_TARGETS_CONNECT_PREFIX */
        static const char *connect_prefixes[] = {
            "/Applications/Jamf Connect.app/",
            "/Applications/Jamf Connect Configuration.app/",
            "/Library/Application Support/JamfConnect/",
            NULL
        };
        /* WATCHDOG_TARGETS_CONNECT_PREFIX_END */
        for (int i = 0; connect_exact[i]; i++)
            if (strcmp(path, connect_exact[i]) == 0) return 1;
        for (int i = 0; connect_prefixes[i]; i++)
            if (has_prefix(path, connect_prefixes[i])) return 1;
    }
    return 0;
}

static int signing_identifier(pid_t pid, char *out, size_t out_size) {
    CFNumberRef num = CFNumberCreate(kCFAllocatorDefault, kCFNumberIntType, &pid);
    if (!num) return 0;
    const void *keys[] = { kSecGuestAttributePid };
    const void *vals[] = { num };
    CFDictionaryRef attrs = CFDictionaryCreate(kCFAllocatorDefault, keys, vals, 1,
        &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    CFRelease(num);
    if (!attrs) return 0;
    SecCodeRef code = NULL;
    OSStatus status = SecCodeCopyGuestWithAttributes(NULL, attrs, kSecCSDefaultFlags, &code);
    CFRelease(attrs);
    if (status != errSecSuccess || !code) return 0;
    CFDictionaryRef info = NULL;
    status = SecCodeCopySigningInformation(code, kSecCSSigningInformation, &info);
    CFRelease(code);
    if (status != errSecSuccess || !info) return 0;
    CFStringRef ident = CFDictionaryGetValue(info, kSecCodeInfoIdentifier);
    int ok = 0;
    if (ident && CFGetTypeID(ident) == CFStringGetTypeID())
        ok = CFStringGetCString(ident, out, (CFIndex)out_size, kCFStringEncodingUTF8);
    CFRelease(info);
    return ok;
}

static int target_path(const char *path, pid_t pid) {
    if (test_target) return strcmp(path, test_target) == 0;
    const char *data = "/System/Volumes/Data";
    if (strncmp(path, data, strlen(data)) == 0) path += strlen(data);
    if (excluded_path(path)) return 0;
    if (path_matches(path)) return 1;
    if (match_signature) {
        char ident[256] = {0};
        if (signing_identifier(pid, ident, sizeof(ident)) && identifier_allowed(ident))
            return 1;
    }
    return 0;
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
        int selected = proc_pidpath(pids[i], path, sizeof(path)) > 0 && target_path(path, pids[i]);
        out[used++] = (Entry){pids[i], (pid_t)info.pbi_ppid, (pid_t)info.pbi_pgid,
                              info.pbi_start_tvsec, info.pbi_start_tvusec, selected};
    }
    free(pids);
    *entries = out;
    return used;
}

static void mark_descendants(Entry *entries, int count) {
    int changed;
    do {
        changed = 0;
        for (int i = 0; i < count; i++) {
            if (entries[i].selected) continue;
            for (int j = 0; j < count; j++) {
                if (!entries[j].selected) continue;
                if (entries[i].ppid == entries[j].pid) {
                    entries[i].selected = 1;
                    changed = 1;
                    break;
                }
                /* Only follow a group owned by the selected process (pgid == that
                   pid). Matching every shared pgid would kill an inherited parent
                   group — shells, the test runner, unrelated launchd siblings. */
                if (entries[j].pid > 1 && entries[i].pgid == entries[j].pid) {
                    entries[i].selected = 1;
                    changed = 1;
                    break;
                }
            }
        }
    } while (changed);
}

static int parse_args(int argc, char **argv) {
    const char *test_identifier = NULL;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--test-target") == 0 && i + 1 < argc && argv[i + 1][0] == '/') {
            test_target = argv[++i];
        } else if (strcmp(argv[i], "--test-identifier") == 0 && i + 1 < argc) {
            test_identifier = argv[++i];
        } else if (strcmp(argv[i], "--interval-ms") == 0 && i + 1 < argc) {
            long ms = strtol(argv[++i], NULL, 10);
            if (ms < 1) ms = 1;
            if (ms > 2000) ms = 2000;
            interval_ns = ms * 1000000L;
        } else if (strcmp(argv[i], "--match-signature") == 0) {
            match_signature = 1;
        } else if (strcmp(argv[i], "--block-connect") == 0) {
            block_connect = 1;
        } else {
            fprintf(stderr, "Unknown argument: %s\n", argv[i]);
            return 2;
        }
    }
    if (test_identifier) {
        int allowed = identifier_allowed(test_identifier);
        fprintf(stdout, "%s\n", allowed ? "allow" : "deny");
        return allowed ? 10 : 11;
    }
    if (!test_target && geteuid() != 0) {
        fprintf(stderr, "Run installed WatchDog monitor as root, or use --test-target /absolute/test/executable.\n");
        return 2;
    }
    return 0;
}

int main(int argc, char **argv) {
    int parsed = parse_args(argc, argv);
    if (parsed == 10 || parsed == 11) return parsed == 10 ? 0 : 1;
    if (parsed != 0) return parsed;
    signal(SIGTERM, stop);
    signal(SIGINT, stop);
    setvbuf(stderr, NULL, _IOLBF, 0);
    fprintf(stderr, "WatchDog monitor started; %ld ms polling; mode=%s.\n",
            interval_ns / 1000000L, test_target ? "isolated test" : "Jamf local components");
    while (running) {
        Entry *entries = NULL;
        int count = snapshot(&entries), found = 0;
        if (count < 0) { fprintf(stderr, "Process enumeration failed.\n"); return 1; }
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
            mark_descendants(entries, count);
            for (int i = 0; i < count; i++)
                if (entries[i].selected && same_process(&entries[i])) (void)kill(entries[i].pid, SIGSTOP);
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
        struct timespec delay = { .tv_sec = interval_ns / 1000000000L, .tv_nsec = interval_ns % 1000000000L };
        while (running && nanosleep(&delay, &delay) == -1 && errno == EINTR) {}
    }
    fprintf(stderr, "WatchDog monitor stopped.\n");
    return 0;
}
