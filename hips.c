#include <pthread.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <errno.h>
#include <pwd.h>
#include <signal.h>         /* SIGSTOP, SIGKILL, SIGCONT, kill() */
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

typedef pthread_t hp_thread_t;
typedef uid_t     hp_uid_t;

#define HP_SLEEP_MS(ms) usleep((ms) * 1000)

/* Suspicious path prefixes on Linux */
static const char* SUSPICIOUS_PATHS[] = {
    "/tmp/",
    "/dev/shm/",
    "/var/tmp/",
    "/run/user/",
    NULL
};

/* Poll interval for each module (milliseconds) */
#define POLL_INTERVAL_MS   1000

/* Maximum processes we track per snapshot */
#define MAX_PROCESSES      1024

/* Maximum TCP connections we track per snapshot */
#define MAX_CONNECTIONS    512

/* ============================================================
 * SECTION 2: Alert system
 * ============================================================
 * Single function all modules use to emit alerts.
 * Format: [HIPS][SEVERITY] message
 * ============================================================ */

typedef enum {
    ALERT_LOW    = 0,
    ALERT_MEDIUM = 1,
    ALERT_HIGH   = 2
} AlertLevel;

static const char* alert_label[] = { "LOW", "MEDIUM", "HIGH" };

static void hp_alert(AlertLevel level, const char* module, const char* fmt, ...) {
    char msg[1024];
    va_list args;
    va_start(args, fmt);
    vsnprintf(msg, sizeof(msg), fmt, args);
    va_end(args);
    printf("[HIPS][%s][%s] %s\n", alert_label[level], module, msg);
    fflush(stdout);
}

/* ============================================================
 * SECTION 2.5: Response system
 * ============================================================
 * ResponseMode  — what to do when an alert fires
 * response_policy[] — maps each AlertLevel to a ResponseMode
 *
 * RESPONSE MODES:
 *   RESPONSE_ALERT_ONLY    — log the alert, do nothing to process
 *   RESPONSE_ALERT_SUSPEND — log + freeze process (SIGSTOP)
 *   RESPONSE_ALERT_KILL    — log + terminate process (SIGKILL)
 * ============================================================ */

typedef enum {
    RESPONSE_ALERT_ONLY    = 0,
    RESPONSE_ALERT_SUSPEND = 1,
    RESPONSE_ALERT_KILL    = 2
} ResponseMode;

/*
 * response_policy — one entry per AlertLevel.
 *   LOW    → alert only    (too noisy, many false positives)
 *   MEDIUM → suspend       (suspicious but not certain — freeze and investigate)
 *   HIGH   → kill          (high confidence threat — terminate immediately)
 */
static ResponseMode response_policy[] = {
    [ALERT_LOW]    = RESPONSE_ALERT_ONLY,
    [ALERT_MEDIUM] = RESPONSE_ALERT_SUSPEND,
    [ALERT_HIGH]   = RESPONSE_ALERT_KILL,
};

static const char* response_label[] = { "ALERT_ONLY", "SUSPENDED", "KILLED" };

/* ── Suspended process log ─────────────────────────────────── */
#define MAX_SUSPENDED 128

typedef struct {
    unsigned long pid;
    char          name[256];
    char          reason[512];
    int           active;        /* 1 = still suspended, 0 = resumed or killed */
} SuspendedEntry;

static SuspendedEntry suspended_log[MAX_SUSPENDED];
static int            suspended_count = 0;

static int suspended_log_add(unsigned long pid, const char* name, const char* reason) {
    if (suspended_count >= MAX_SUSPENDED) return -1;
    int idx = suspended_count++;
    suspended_log[idx].pid    = pid;
    suspended_log[idx].active = 1;
    strncpy(suspended_log[idx].name,   name,   sizeof(suspended_log[idx].name)   - 1);
    strncpy(suspended_log[idx].reason, reason, sizeof(suspended_log[idx].reason) - 1);
    suspended_log[idx].name  [sizeof(suspended_log[idx].name)   - 1] = '\0';
    suspended_log[idx].reason[sizeof(suspended_log[idx].reason) - 1] = '\0';
    return idx;
}

/* ── hp_resume_process ─────────────────────────────────────── */
/*
 * Resumes a suspended process by PID.
 * SIGCONT restarts a process frozen with SIGSTOP.
 */
static void hp_resume_process(unsigned long pid) {
    if (kill((pid_t)pid, SIGCONT) == 0) {
        printf("[HIPS][RESPONSE] Resumed pid=%lu\n", pid);
    } else {
        perror("[HIPS][RESPONSE] Failed to resume");
    }
    fflush(stdout);

    /* Mark inactive in log */
    for (int i = 0; i < suspended_count; i++) {
        if (suspended_log[i].pid == pid && suspended_log[i].active) {
            suspended_log[i].active = 0;
            break;
        }
    }
}

/* ── hp_respond ────────────────────────────────────────────── */
/*
 * Executes the response action for a given alert level and PID.
 * If pid == 0, no process action is taken.
 */
static void hp_respond(AlertLevel level, unsigned long pid,
                       const char* proc_name, const char* alert_msg) {
    if (pid == 0) return;

    ResponseMode mode = response_policy[level];
    if (mode == RESPONSE_ALERT_ONLY) return;

    printf("[HIPS][RESPONSE][%s] pid=%lu name=%s\n",
           response_label[mode], pid, proc_name ? proc_name : "unknown");
    fflush(stdout);

    if (mode == RESPONSE_ALERT_SUSPEND) {
        /*
         * SIGSTOP cannot be caught or ignored by the target process.
         * Stronger than SIGTSTP. Frozen until SIGCONT is sent.
         */
        if (kill((pid_t)pid, SIGSTOP) != 0)
            perror("[HIPS][RESPONSE] SIGSTOP failed");
        suspended_log_add(pid, proc_name ? proc_name : "unknown", alert_msg);

    } else if (mode == RESPONSE_ALERT_KILL) {
        if (kill((pid_t)pid, SIGKILL) != 0)
            perror("[HIPS][RESPONSE] SIGKILL failed");
    }
}

/*
 * hp_alert_and_respond() — the function modules actually call.
 * Combines alert emission + response in one call.
 * pid = 0 means "no specific process" — alert fires but no kill/suspend.
 */
static void hp_alert_and_respond(AlertLevel level, const char* module,
                                 unsigned long pid, const char* proc_name,
                                 const char* fmt, ...) {
    char msg[1024];
    va_list args;
    va_start(args, fmt);
    vsnprintf(msg, sizeof(msg), fmt, args);
    va_end(args);

    printf("[HIPS][%s][%s] %s\n", alert_label[level], module, msg);
    fflush(stdout);

    hp_respond(level, pid, proc_name, msg);
}

/* ============================================================
 * SECTION 3: Platform abstraction
 * ============================================================
 * ProcessEntry          — one running process
 * hp_get_process_list() — fills an array of ProcessEntry
 * hp_is_suspicious_path()
 * hp_create_thread()
 * ============================================================ */

typedef struct {
    unsigned long pid;
    unsigned long ppid;
    char          name[256];
    char          path[PATH_MAX];
    hp_uid_t      uid;
} ProcessEntry;

static int hp_is_suspicious_path(const char* path) {
    for (int i = 0; SUSPICIOUS_PATHS[i] != NULL; i++) {
        if (strncmp(path, SUSPICIOUS_PATHS[i], strlen(SUSPICIOUS_PATHS[i])) == 0)
            return 1;
    }
    return 0;
}

/*
 * hp_get_process_list — reads /proc to enumerate all running processes.
 *
 * /proc/PID/status  → Name, Pid, PPid, Uid
 * /proc/PID/exe     → symlink to the actual executable path
 */
static int hp_get_process_list(ProcessEntry* out, int max) {
    int count = 0;

    DIR* proc = opendir("/proc");
    if (!proc) return 0;

    struct dirent* entry;
    while ((entry = readdir(proc)) != NULL && count < max) {

        /* Skip non-numeric entries — only PIDs are pure digits */
        int is_pid = 1;
        for (int i = 0; entry->d_name[i]; i++) {
            if (entry->d_name[i] < '0' || entry->d_name[i] > '9') {
                is_pid = 0;
                break;
            }
        }
        if (!is_pid) continue;

        ProcessEntry* e = &out[count];
        e->pid  = (unsigned long)atol(entry->d_name);
        e->ppid = 0;
        e->name[0] = '\0';
        e->path[0] = '\0';
        e->uid  = (hp_uid_t)-1;

        char pid_str[16];
        strncpy(pid_str, entry->d_name, sizeof(pid_str) - 1);
        pid_str[sizeof(pid_str) - 1] = '\0';

        /* Read /proc/PID/status for name, ppid, uid */
        char status_path[64];
        snprintf(status_path, sizeof(status_path), "/proc/%s/status", pid_str);
        FILE* f = fopen(status_path, "r");
        if (f) {
            char line[256];
            while (fgets(line, sizeof(line), f)) {
                if (strncmp(line, "Name:", 5) == 0)
                    sscanf(line, "Name:\t%255s", e->name);
                else if (strncmp(line, "PPid:", 5) == 0)
                    sscanf(line, "PPid:\t%lu", &e->ppid);
                else if (strncmp(line, "Uid:", 4) == 0) {
                    unsigned long ruid, euid;
                    sscanf(line, "Uid:\t%lu\t%lu", &ruid, &euid);
                    e->uid = (hp_uid_t)euid;  /* effective UID is what matters */
                }
            }
            fclose(f);
        }

        /* Read /proc/PID/exe symlink for full path */
        char exe_path[64];
        snprintf(exe_path, sizeof(exe_path), "/proc/%s/exe", pid_str);
        ssize_t len = readlink(exe_path, e->path, PATH_MAX - 1);
        if (len > 0)
            e->path[len] = '\0';

        count++;
    }
    closedir(proc);

    return count;
}

/*
 * hp_get_uid_of_pid — returns the effective UID of a specific PID.
 * Used by mod_privesc. Returns (hp_uid_t)-1 on failure.
 */
static hp_uid_t hp_get_uid_of_pid(unsigned long pid) {
    ProcessEntry buf[MAX_PROCESSES];
    int count = hp_get_process_list(buf, MAX_PROCESSES);
    for (int i = 0; i < count; i++) {
        if (buf[i].pid == pid)
            return buf[i].uid;
    }
    return (hp_uid_t)-1;
}

static int hp_create_thread(hp_thread_t* t, void* (*fn)(void*), void* arg) {
    return pthread_create(t, NULL, fn, arg);
}

/* ============================================================
 * SECTION 4: mod_process
 * ============================================================
 * Detects new processes that spawn from suspicious paths.
 *
 * How it works:
 *   - Every POLL_INTERVAL_MS, snapshot all running PIDs
 *   - Diff against the previous snapshot
 *   - Any PID not seen before = new process
 *   - Check its executable path against SUSPICIOUS_PATHS[]
 *   - Emit HIGH alert if suspicious, LOW if just new (informational)
 * ============================================================ */

static void* mod_process_run(void* arg) {
    (void)arg;

    static unsigned long prev_pids[MAX_PROCESSES];
    static int           prev_count = 0;
    ProcessEntry         current[MAX_PROCESSES];

    printf("[HIPS] mod_process started\n");
    fflush(stdout);

    while (1) {
        int current_count = hp_get_process_list(current, MAX_PROCESSES);

        for (int i = 0; i < current_count; i++) {
            unsigned long pid = current[i].pid;
            int is_new = 1;

            for (int j = 0; j < prev_count; j++) {
                if (prev_pids[j] == pid) {
                    is_new = 0;
                    break;
                }
            }

            if (is_new) {
                if (current[i].path[0] != '\0' && hp_is_suspicious_path(current[i].path)) {
                    hp_alert_and_respond(ALERT_HIGH, "mod_process", pid, current[i].name,
                        "New process from suspicious path | pid=%lu name=%s path=%s",
                        pid, current[i].name, current[i].path);
                } else {
                    hp_alert_and_respond(ALERT_LOW, "mod_process", pid, current[i].name,
                        "New process | pid=%lu name=%s",
                        pid, current[i].name);
                }
            }
        }

        prev_count = current_count > MAX_PROCESSES ? MAX_PROCESSES : current_count;
        for (int i = 0; i < prev_count; i++)
            prev_pids[i] = current[i].pid;

        HP_SLEEP_MS(POLL_INTERVAL_MS);
    }
    return NULL;
}

/* ============================================================
 * SECTION 5: mod_privesc
 * ============================================================
 * Detects privilege escalation — a process whose UID was
 * non-zero (unprivileged) becomes zero (root).
 * ============================================================ */

typedef struct {
    unsigned long pid;
    hp_uid_t      uid;
} UidSnapshot;

static void* mod_privesc_run(void* arg) {
    (void)arg;

    static UidSnapshot prev[MAX_PROCESSES];
    static int         prev_count = 0;
    ProcessEntry       current[MAX_PROCESSES];

    printf("[HIPS] mod_privesc started\n");
    fflush(stdout);

    while (1) {
        int current_count = hp_get_process_list(current, MAX_PROCESSES);

        for (int i = 0; i < current_count; i++) {
            unsigned long pid = current[i].pid;
            hp_uid_t      uid = current[i].uid;

            for (int j = 0; j < prev_count; j++) {
                if (prev[j].pid == pid) {
                    /* UID was non-zero and is now zero → privilege escalation */
                    if (prev[j].uid != 0 && uid == 0) {
                        hp_alert_and_respond(ALERT_HIGH, "mod_privesc", pid, current[i].name,
                            "Privilege escalation detected | pid=%lu name=%s uid %lu -> 0",
                            pid, current[i].name, (unsigned long)prev[j].uid);
                    }
                    break;
                }
            }
        }

        prev_count = current_count > MAX_PROCESSES ? MAX_PROCESSES : current_count;
        for (int i = 0; i < prev_count; i++) {
            prev[i].pid = current[i].pid;
            prev[i].uid = current[i].uid;
        }

        HP_SLEEP_MS(POLL_INTERVAL_MS);
    }
    return NULL;
}

/* ============================================================
 * SECTION 6: mod_parentchild
 * ============================================================
 * Detects suspicious parent→child process relationships.
 * Example: a browser spawning a shell, or a document reader
 * spawning a scripting engine.
 * ============================================================ */

typedef struct {
    const char* parent;
    const char* child;
    AlertLevel  level;
} ParentChildRule;

/*
 * Rule table — extend this list to add new detections.
 * Uses substring matching so "chrome" matches "chrome.exe" etc.
 * Terminated by a {NULL, NULL} sentinel.
 */
static const ParentChildRule PC_RULES[] = {
    { "chrome",     "bash",        ALERT_HIGH   },
    { "firefox",    "bash",        ALERT_HIGH   },
    { "python",     "chmod",       ALERT_MEDIUM },
    { "python",     "chown",       ALERT_MEDIUM },
    { "java",       "bash",        ALERT_MEDIUM },
    { NULL,         NULL,          ALERT_LOW    }   /* sentinel */
};

static void* mod_parentchild_run(void* arg) {
    (void)arg;

    static unsigned long seen_pids[MAX_PROCESSES];
    static int           seen_count = 0;
    ProcessEntry         current[MAX_PROCESSES];

    printf("[HIPS] mod_parentchild started\n");
    fflush(stdout);

    while (1) {
        int current_count = hp_get_process_list(current, MAX_PROCESSES);

        for (int i = 0; i < current_count; i++) {
            unsigned long pid = current[i].pid;

            int already_seen = 0;
            for (int s = 0; s < seen_count; s++) {
                if (seen_pids[s] == pid) { already_seen = 1; break; }
            }
            if (already_seen) continue;

            /* Find parent's name by matching ppid to another entry */
            const char* parent_name = "";
            for (int j = 0; j < current_count; j++) {
                if (current[j].pid == current[i].ppid) {
                    parent_name = current[j].name;
                    break;
                }
            }

            for (int r = 0; PC_RULES[r].parent != NULL; r++) {
                int parent_match = (strstr(parent_name,      PC_RULES[r].parent) != NULL);
                int child_match  = (strstr(current[i].name,  PC_RULES[r].child)  != NULL);

                if (parent_match && child_match) {
                    hp_alert_and_respond(PC_RULES[r].level, "mod_parentchild", pid, current[i].name,
                        "Suspicious parent->child | %s (pid=%lu) -> %s (pid=%lu)",
                        parent_name, current[i].ppid,
                        current[i].name, pid);
                }
            }

            if (seen_count < MAX_PROCESSES)
                seen_pids[seen_count++] = pid;
        }

        HP_SLEEP_MS(POLL_INTERVAL_MS);
    }
    return NULL;
}

/* ============================================================
 * SECTION 7: mod_network
 * ============================================================
 * Detects processes making new outbound TCP connections.
 * Reads /proc/net/tcp, resolves inode → PID via /proc/PID/fd/
 *
 * Flags:
 *   - Any process making a connection from a suspicious path → HIGH
 *   - Any new external connection (not loopback)            → LOW
 * ============================================================ */

typedef struct {
    unsigned long  pid;
    unsigned long  remote_ip;
    unsigned short remote_port;
} ConnSnapshot;

/*
 * parse_proc_net_tcp — reads /proc/net/tcp for active (ESTABLISHED,
 * non-loopback) connections, then resolves each inode to its owning PID
 * by scanning /proc/PID/fd/ for a matching socket symlink.
 *
 * /proc/net/tcp columns (hex):
 *   sl  local_address  rem_address  st  ...  inode
 */
static int parse_proc_net_tcp(ConnSnapshot* conn_out, int max) {
    FILE* f = fopen("/proc/net/tcp", "r");
    if (!f) return 0;

    int count = 0;
    char line[512];
    fgets(line, sizeof(line), f);  /* skip header */

    while (fgets(line, sizeof(line), f) && count < max) {
        unsigned long local_ip, remote_ip;
        unsigned int  local_port, remote_port;
        unsigned int  state, inode;
        unsigned int  dummy_u;
        unsigned long dummy_l;

        int parsed = sscanf(line,
            " %u: %lX:%X %lX:%X %X %lX:%lX %X:%X %X %u %u %u",
            &dummy_u,
            &local_ip,  &local_port,
            &remote_ip, &remote_port,
            &state,
            &dummy_l,   &dummy_l,
            &dummy_u,   &dummy_u,
            &dummy_u,
            &dummy_u,   &dummy_u,
            &inode);

        if (parsed < 14) continue;
        if (state != 1)  continue;  /* 01 = TCP_ESTABLISHED only */

        /* Skip loopback (127.x.x.x) */
        if ((remote_ip & 0xFF) == 127) continue;

        /*
         * Resolve inode → PID.
         * Walk /proc/PID/fd/ looking for a symlink "socket:[inode]".
         */
        unsigned long owner_pid = 0;
        char socket_target[64];
        snprintf(socket_target, sizeof(socket_target), "socket:[%u]", inode);

        DIR* proc = opendir("/proc");
        if (proc) {
            struct dirent* pe;
            while ((pe = readdir(proc)) != NULL && owner_pid == 0) {
                int is_pid = 1;
                for (int k = 0; pe->d_name[k]; k++)
                    if (pe->d_name[k] < '0' || pe->d_name[k] > '9') { is_pid = 0; break; }
                if (!is_pid) continue;

                char pid_str2[16];
                strncpy(pid_str2, pe->d_name, sizeof(pid_str2) - 1);
                pid_str2[sizeof(pid_str2) - 1] = '\0';

                char fd_dir[64];
                snprintf(fd_dir, sizeof(fd_dir), "/proc/%s/fd", pid_str2);
                DIR* fdd = opendir(fd_dir);
                if (!fdd) continue;

                struct dirent* fde;
                while ((fde = readdir(fdd)) != NULL) {
                    char fd_name[16];
                    strncpy(fd_name, fde->d_name, sizeof(fd_name) - 1);
                    fd_name[sizeof(fd_name) - 1] = '\0';
                    char fd_path[128], link_target[256];
                    snprintf(fd_path, sizeof(fd_path), "%s/%s", fd_dir, fd_name);
                    ssize_t len = readlink(fd_path, link_target, sizeof(link_target) - 1);
                    if (len > 0) {
                        link_target[len] = '\0';
                        if (strcmp(link_target, socket_target) == 0) {
                            owner_pid = (unsigned long)atol(pe->d_name);
                            break;
                        }
                    }
                }
                closedir(fdd);
            }
            closedir(proc);
        }

        conn_out[count].pid         = owner_pid;
        conn_out[count].remote_ip   = remote_ip;
        conn_out[count].remote_port = (unsigned short)remote_port;
        count++;
    }

    fclose(f);
    return count;
}

static void* mod_network_run(void* arg) {
    (void)arg;

    static ConnSnapshot prev[MAX_CONNECTIONS];
    static int          prev_count = 0;
    ConnSnapshot        current[MAX_CONNECTIONS];
    ProcessEntry        procs[MAX_PROCESSES];

    printf("[HIPS] mod_network started\n");
    fflush(stdout);

    while (1) {
        int current_count = parse_proc_net_tcp(current, MAX_CONNECTIONS);

        int proc_count = hp_get_process_list(procs, MAX_PROCESSES);

        for (int i = 0; i < current_count; i++) {
            int is_new = 1;
            for (int j = 0; j < prev_count; j++) {
                if (current[i].pid         == prev[j].pid &&
                    current[i].remote_ip   == prev[j].remote_ip &&
                    current[i].remote_port == prev[j].remote_port) {
                    is_new = 0;
                    break;
                }
            }
            if (!is_new) continue;

            const char* proc_name = "unknown";
            const char* proc_path = "";
            for (int p = 0; p < proc_count; p++) {
                if (procs[p].pid == current[i].pid) {
                    proc_name = procs[p].name;
                    proc_path = procs[p].path;
                    break;
                }
            }

            /* Linux /proc/net/tcp stores IP in little-endian hex */
            unsigned long rip = current[i].remote_ip;
            char ip_str[32];
            snprintf(ip_str, sizeof(ip_str), "%lu.%lu.%lu.%lu",
                 rip        & 0xFF, (rip >>  8) & 0xFF,
                (rip >> 16) & 0xFF, (rip >> 24) & 0xFF);

            if (proc_path[0] != '\0' && hp_is_suspicious_path(proc_path)) {
                hp_alert_and_respond(ALERT_HIGH, "mod_network", current[i].pid, proc_name,
                    "Suspicious process making connection | pid=%lu name=%s path=%s -> %s:%u",
                    current[i].pid, proc_name, proc_path,
                    ip_str, current[i].remote_port);
            } else {
                hp_alert_and_respond(ALERT_LOW, "mod_network", current[i].pid, proc_name,
                    "New outbound connection | pid=%lu name=%s -> %s:%u",
                    current[i].pid, proc_name,
                    ip_str, current[i].remote_port);
            }
        }

        prev_count = current_count > MAX_CONNECTIONS ? MAX_CONNECTIONS : current_count;
        memcpy(prev, current, prev_count * sizeof(ConnSnapshot));

        HP_SLEEP_MS(POLL_INTERVAL_MS);
    }
    return NULL;
}

/* ============================================================
 * SECTION 8: Module registry & main()
 * ============================================================
 * TO DISABLE A MODULE: set .enabled = 0
 * TO ADD A MODULE:     append a new entry, no other changes needed
 * ============================================================ */

typedef struct {
    const char*  name;
    int          enabled;
    void*        (*run)(void*);
} HipsModule;

static HipsModule module_registry[] = {
    { "mod_process",     1, mod_process_run     },
    { "mod_privesc",     1, mod_privesc_run      },
    { "mod_parentchild", 1, mod_parentchild_run  },
    { "mod_network",     1, mod_network_run      },
    /* Add new modules here ↑ */
};

#define MODULE_COUNT (sizeof(module_registry) / sizeof(module_registry[0]))

int main(void) {
    printf("[HIPS] Black Swan HIPS-lite starting...\n");
    printf("[HIPS] %zu module(s) registered\n", MODULE_COUNT);
    fflush(stdout);

    hp_thread_t threads[MODULE_COUNT];
    int         spawned = 0;

    for (int i = 0; i < (int)MODULE_COUNT; i++) {
        if (!module_registry[i].enabled) {
            printf("[HIPS] %s is DISABLED — skipping\n", module_registry[i].name);
            fflush(stdout);
            continue;
        }

        if (hp_create_thread(&threads[i], module_registry[i].run, NULL) != 0) {
            fprintf(stderr, "[HIPS] Failed to start %s\n", module_registry[i].name);
        } else {
            printf("[HIPS] %s started\n", module_registry[i].name);
            fflush(stdout);
            spawned++;
        }
    }

    if (spawned == 0) {
        fprintf(stderr, "[HIPS] No modules started. Exiting.\n");
        return 1;
    }

    /*
     * stdin command loop — the GUI can send commands to control HIPS.
     *
     * Commands:
     *   q              → quit HIPS
     *   resume <pid>   → resume a suspended process by PID
     *   list           → print all currently suspended processes
     */
    printf("[HIPS] Running. Commands: 'q' = quit | 'resume <pid>' = resume | 'list' = show suspended\n");
    fflush(stdout);

    char cmd[64];
    while (fgets(cmd, sizeof(cmd), stdin)) {
        cmd[strcspn(cmd, "\n")] = '\0';

        if (strcmp(cmd, "q") == 0) {
            break;

        } else if (strncmp(cmd, "resume ", 7) == 0) {
            unsigned long pid = (unsigned long)atol(cmd + 7);
            if (pid > 0) {
                hp_resume_process(pid);
            } else {
                printf("[HIPS] Invalid PID for resume\n");
                fflush(stdout);
            }

        } else if (strcmp(cmd, "list") == 0) {
            int found = 0;
            printf("[HIPS][SUSPENDED_LIST]\n");
            for (int i = 0; i < suspended_count; i++) {
                if (suspended_log[i].active) {
                    printf("  pid=%-8lu name=%-20s reason=%s\n",
                        suspended_log[i].pid,
                        suspended_log[i].name,
                        suspended_log[i].reason);
                    found++;
                }
            }
            if (!found)
                printf("  (none)\n");
            printf("[HIPS][SUSPENDED_LIST_END]\n");
            fflush(stdout);
        }
    }

    printf("[HIPS] Shutting down.\n");
    return 0;
}

