#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <dirent.h>
#include <pthread.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/syscall.h>
#include <limits.h>

#ifndef PTRACE_O_TRACESYSGOOD
#define PTRACE_O_TRACESYSGOOD 0x00000001
#endif
#ifndef PTRACE_O_EXITKILL
#define PTRACE_O_EXITKILL     0x00100000
#endif

#define POLL_INTERVAL_MS      1000
#define MAX_PROCESSES         1024
#define MAX_WATCHED           64

#define HP_SLEEP_MS(ms) usleep((ms) * 1000)

/* ============================================================
 * SECTION 2: Alert system
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
    printf("[DEEP][%s][%s] %s\n", alert_label[level], module, msg);
    fflush(stdout);
}

/* ============================================================
 * SECTION 3: Syscall name table
 * ============================================================
 * Maps syscall numbers to human-readable names.
 * Only maps security-relevant ones — everything else is "syscall_NNN".
 * ============================================================ */

typedef struct {
    long        number;
    const char* name;
} SyscallName;

static const SyscallName SYSCALL_NAMES[] = {
    { SYS_read,          "read"          },
    { SYS_write,         "write"         },
    { SYS_open,          "open"          },
    { SYS_close,         "close"         },
    { SYS_execve,        "execve"        },
    { SYS_fork,          "fork"          },
    { SYS_clone,         "clone"         },
    { SYS_connect,       "connect"       },
    { SYS_chmod,         "chmod"         },
    { SYS_chown,         "chown"         },
    { SYS_unlink,        "unlink"        },
    { SYS_rename,        "rename"        },
    { SYS_kill,          "kill"          },
    { SYS_ptrace,        "ptrace"        },
    { SYS_openat,        "openat"        },
    { SYS_unlinkat,      "unlinkat"      },
    { SYS_renameat,      "renameat"      },
    { SYS_socket,        "socket"        },
    { SYS_bind,          "bind"          },
    { SYS_listen,        "listen"        },
    { SYS_setuid,        "setuid"        },
    { SYS_setgid,        "setgid"        },
    { SYS_setreuid,      "setreuid"      },
    { SYS_getuid,        "getuid"        },
    { -1,                NULL            }
};

static const char* syscall_name(long nr) {
    static char buf[32];
    for (int i = 0; SYSCALL_NAMES[i].name != NULL; i++) {
        if (SYSCALL_NAMES[i].number == nr)
            return SYSCALL_NAMES[i].name;
    }
    snprintf(buf, sizeof(buf), "syscall_%ld", nr);
    return buf;
}

/* ============================================================
 * SECTION 4: Sensitive path & syscall filter lists
 * ============================================================ */

static const char* SENSITIVE_PATHS[] = {
    "/etc/passwd",
    "/etc/shadow",
    "/etc/sudoers",
    "/etc/cron",
    "/root/",
    "/home/",
    "/var/log/auth",
    NULL
};

static const char* SUSPICIOUS_PROC_PATHS[] = {
    "/tmp/",
    "/dev/shm/",
    "/var/tmp/",
    "/run/user/",
    NULL
};

/*
 * Syscalls that are always interesting when called by a suspicious process.
 * execve = spawning a new binary (potential dropper chain)
 * connect = network activity
 * listen  = opening a backdoor port
 * setuid  = privilege escalation attempt
 * ptrace  = anti-debugging or process injection
 * unlink  = self-deletion (covering tracks)
 */
static const long ALERT_SYSCALLS[] = {
    SYS_execve,
    SYS_connect,
    SYS_listen,
    SYS_setuid,
    SYS_setreuid,
    SYS_ptrace,
    SYS_unlink,
    SYS_unlinkat,
    SYS_kill,
    -1
};

static int is_suspicious_proc_path(const char* path) {
    for (int i = 0; SUSPICIOUS_PROC_PATHS[i]; i++)
        if (strncmp(path, SUSPICIOUS_PROC_PATHS[i], strlen(SUSPICIOUS_PROC_PATHS[i])) == 0)
            return 1;
    return 0;
}

static int is_sensitive_path(const char* path) {
    for (int i = 0; SENSITIVE_PATHS[i]; i++)
        if (strncmp(path, SENSITIVE_PATHS[i], strlen(SENSITIVE_PATHS[i])) == 0)
            return 1;
    return 0;
}

static int is_alert_syscall(long nr) {
    for (int i = 0; ALERT_SYSCALLS[i] != -1; i++)
        if (ALERT_SYSCALLS[i] == nr) return 1;
    return 0;
}

/* ============================================================
 * SECTION 5: Passive syscall reader
 * ============================================================
 * /proc/PID/syscall exposes the syscall a process is CURRENTLY
 * executing — the syscall number and its arguments.
 *
 * WHY THIS IS LIGHTWEIGHT:
 *   - Just a file read — no kernel hooks, no attachment
 *   - Zero impact on the monitored process
 *   - Works without root for processes owned by the current user
 *   - Tradeoff: only sees what's happening AT the moment we read
 * ============================================================ */

/*
 * read_current_syscall — reads /proc/PID/syscall for a given PID.
 * Returns the syscall number, or -1 if the process isn't in a syscall.
 * Fills arg0_out with the first argument (often a file descriptor or pointer).
 */
static long read_current_syscall(unsigned long pid, unsigned long* arg0_out) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%lu/syscall", pid);

    FILE* f = fopen(path, "r");
    if (!f) return -1;

    long nr = -1;
    unsigned long arg0 = 0;

    char first[32];
    if (fscanf(f, "%31s", first) == 1) {
        if (strcmp(first, "running") != 0 && strcmp(first, "-1") != 0) {
            nr = strtol(first, NULL, 10);
            fscanf(f, " %lx", &arg0);
            if (arg0_out) *arg0_out = arg0;
        }
    }

    fclose(f);
    return nr;
}

/*
 * try_read_string_from_proc — reads a string from another process's
 * memory via /proc/PID/mem. Used to resolve path arguments from syscalls.
 * Returns 1 on success, 0 on failure.
 */
static int try_read_string_from_proc(unsigned long pid, unsigned long addr,
                                      char* out, size_t out_size) {
    char mem_path[64];
    snprintf(mem_path, sizeof(mem_path), "/proc/%lu/mem", pid);

    FILE* f = fopen(mem_path, "rb");
    if (!f) return 0;

    if (fseeko(f, (off_t)addr, SEEK_SET) != 0) {
        fclose(f);
        return 0;
    }

    size_t n = fread(out, 1, out_size - 1, f);
    out[n] = '\0';

    for (size_t i = 0; i < n; i++) {
        if (out[i] == '\0') break;
        if ((unsigned char)out[i] < 0x20 || (unsigned char)out[i] > 0x7e) {
            out[i] = '\0';
            break;
        }
    }

    fclose(f);
    return (n > 0);
}

/*
 * passive_syscall_scan — scans all running processes once and checks
 * their current syscall via /proc/PID/syscall.
 * Called from the passive monitor thread every POLL_INTERVAL_MS.
 */
static void passive_syscall_scan(void) {
    DIR* proc = opendir("/proc");
    if (!proc) return;

    struct dirent* entry;
    while ((entry = readdir(proc)) != NULL) {

        int is_pid = 1;
        for (int i = 0; entry->d_name[i]; i++) {
            if (entry->d_name[i] < '0' || entry->d_name[i] > '9') {
                is_pid = 0; break;
            }
        }
        if (!is_pid) continue;

        unsigned long pid = (unsigned long)atol(entry->d_name);

        char exe_path[PATH_MAX] = {0};
        char exe_link[64];
        snprintf(exe_link, sizeof(exe_link), "/proc/%lu/exe", pid);
        ssize_t len = readlink(exe_link, exe_path, sizeof(exe_path) - 1);
        if (len > 0) exe_path[len] = '\0';

        unsigned long arg0 = 0;
        long nr = read_current_syscall(pid, &arg0);
        if (nr < 0) continue;

        int proc_suspicious = is_suspicious_proc_path(exe_path);

        /*
         * TWO alert conditions:
         * 1. Any process calling setuid/setreuid → possible privesc
         * 2. Suspicious process calling any alert syscall
         */
        if (nr == SYS_setuid || nr == SYS_setreuid) {
            hp_alert(ALERT_HIGH, "passive_syscall",
                "setuid call detected | pid=%lu exe=%s syscall=%s",
                pid, exe_path[0] ? exe_path : "unknown", syscall_name(nr));

        } else if (proc_suspicious && is_alert_syscall(nr)) {

            char resolved_path[256] = {0};
            int got_path = 0;
            if (nr == SYS_open || nr == SYS_openat || nr == SYS_execve || nr == SYS_unlink) {
                got_path = try_read_string_from_proc(pid, arg0, resolved_path, sizeof(resolved_path));
            }

            if (got_path && is_sensitive_path(resolved_path)) {
                hp_alert(ALERT_HIGH, "passive_syscall",
                    "Suspicious process accessing sensitive file | pid=%lu exe=%s syscall=%s path=%s",
                    pid, exe_path, syscall_name(nr), resolved_path);
            } else {
                hp_alert(ALERT_MEDIUM, "passive_syscall",
                    "Suspicious process syscall | pid=%lu exe=%s syscall=%s",
                    pid, exe_path, syscall_name(nr));
            }
        }
    }

    closedir(proc);
}

static void* passive_monitor_thread(void* arg) {
    (void)arg;
    printf("[DEEP] Passive syscall monitor started (no attachment, /proc/PID/syscall)\n");
    fflush(stdout);

    while (1) {
        passive_syscall_scan();
        HP_SLEEP_MS(POLL_INTERVAL_MS);
    }
    return NULL;
}

/* ============================================================
 * SECTION 6: Active ptrace watcher
 * ============================================================
 * Attaches ptrace to a SPECIFIC suspicious process and intercepts
 * every syscall it makes until it exits.
 *
 * HOW PTRACE SYSCALL INTERCEPTION WORKS:
 *   1. PTRACE_ATTACH  — attach to the process (it pauses)
 *   2. PTRACE_SYSCALL — resume, stop at next syscall entry/exit
 *   3. On each stop   — read registers to get syscall number + args
 *   4. Repeat until process exits
 *
 * Each syscall generates TWO stops (entry + exit).
 * We use a toggle to distinguish them.
 * ============================================================ */

typedef struct {
    unsigned long pid;
    char          exe_path[PATH_MAX];
} PtraceArgs;

/*
 * read_string_via_ptrace — reads a null-terminated string from the
 * tracee's memory using PTRACE_PEEKDATA (word-by-word reads).
 * More reliable than /proc/PID/mem for an attached process.
 */
static void read_string_via_ptrace(pid_t pid, unsigned long addr,
                                    char* out, size_t out_size) {
    size_t i = 0;
    out[0] = '\0';

    while (i < out_size - 1) {
        errno = 0;
        long word = ptrace(PTRACE_PEEKDATA, pid, (void*)(addr + i), NULL);
        if (errno != 0) break;

        char* bytes = (char*)&word;
        for (int b = 0; b < 8 && i < out_size - 1; b++, i++) {
            out[i] = bytes[b];
            if (bytes[b] == '\0') {
                out[i] = '\0';
                return;
            }
        }
    }
    out[i] = '\0';
}

/*
 * ptrace_watch_process — thread function that attaches to and monitors
 * a single suspicious process via ptrace. Runs until process exits.
 */
static void* ptrace_watch_process(void* arg) {
    PtraceArgs* pa  = (PtraceArgs*)arg;
    pid_t        pid = (pid_t)pa->pid;
    char         exe[PATH_MAX];
    strncpy(exe, pa->exe_path, PATH_MAX - 1);
    exe[PATH_MAX - 1] = '\0';
    free(pa);

    printf("[DEEP] Attaching ptrace to pid=%d exe=%s\n", pid, exe);
    fflush(stdout);

    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) < 0) {
        fprintf(stderr, "[DEEP] ptrace attach failed for pid=%d: %s\n",
                pid, strerror(errno));
        return NULL;
    }

    int status;
    waitpid(pid, &status, 0);

    ptrace(PTRACE_SETOPTIONS, pid, NULL,
           (void*)(long)(PTRACE_O_TRACESYSGOOD | PTRACE_O_EXITKILL));

    int in_syscall = 0;

    while (1) {
        if (ptrace(PTRACE_SYSCALL, pid, NULL, NULL) < 0) break;

        int wstatus;
        pid_t result = waitpid(pid, &wstatus, 0);
        if (result < 0) break;

        if (WIFEXITED(wstatus) || WIFSIGNALED(wstatus)) {
            printf("[DEEP] Traced process pid=%d exited\n", pid);
            fflush(stdout);
            break;
        }

        if (!WIFSTOPPED(wstatus)) continue;
        int sig = WSTOPSIG(wstatus);

        /*
         * With PTRACE_O_TRACESYSGOOD, syscall stops = SIGTRAP | 0x80
         * Regular signal stops = actual signal number.
         */
        if (sig != (SIGTRAP | 0x80)) {
            ptrace(PTRACE_SYSCALL, pid, NULL, (void*)(long)sig);
            continue;
        }

        struct user_regs_struct regs;
        if (ptrace(PTRACE_GETREGS, pid, NULL, &regs) < 0) continue;

        /*
         * x86_64 Linux register layout:
         *   orig_rax = syscall number
         *   rdi      = arg0
         *   rsi      = arg1
         */
        long nr = (long)regs.orig_rax;

        if (in_syscall == 0) {
            /* ── SYSCALL ENTRY — read arguments here ── */

            if (is_alert_syscall(nr)) {
                char path_arg[256] = {0};

                if (nr == SYS_open   || nr == SYS_openat ||
                    nr == SYS_execve || nr == SYS_unlink  ||
                    nr == SYS_chmod  || nr == SYS_chown) {

                    unsigned long path_ptr = (nr == SYS_openat)
                        ? (unsigned long)regs.rsi
                        : (unsigned long)regs.rdi;

                    read_string_via_ptrace(pid, path_ptr, path_arg, sizeof(path_arg));
                }

                AlertLevel level = ALERT_MEDIUM;
                const char* reason = "";

                if (nr == SYS_execve) {
                    level  = ALERT_HIGH;
                    reason = " [NEW BINARY EXEC]";
                } else if (nr == SYS_setuid || nr == SYS_setreuid) {
                    level  = ALERT_HIGH;
                    reason = " [PRIVILEGE CHANGE]";
                } else if (nr == SYS_ptrace) {
                    level  = ALERT_HIGH;
                    reason = " [PROCESS TRYING TO PTRACE]";
                } else if (nr == SYS_listen) {
                    level  = ALERT_HIGH;
                    reason = " [OPENING LISTEN PORT — POSSIBLE BACKDOOR]";
                } else if (path_arg[0] && is_sensitive_path(path_arg)) {
                    level  = ALERT_HIGH;
                    reason = " [SENSITIVE FILE ACCESS]";
                }

                if (path_arg[0]) {
                    hp_alert(level, "ptrace",
                        "pid=%d syscall=%s path=%s%s",
                        pid, syscall_name(nr), path_arg, reason);
                } else {
                    hp_alert(level, "ptrace",
                        "pid=%d syscall=%s arg0=0x%llx%s",
                        pid, syscall_name(nr),
                        (unsigned long long)regs.rdi, reason);
                }

                /*
                 * PREVENTION: for execve from a suspicious path,
                 * invalidate the syscall (set orig_rax = -1 → returns ENOSYS)
                 * then send SIGKILL to terminate the process.
                 */
                if (nr == SYS_execve && is_suspicious_proc_path(exe)) {
                    hp_alert(ALERT_HIGH, "ptrace",
                        "BLOCKING execve from suspicious process pid=%d", pid);

                    regs.orig_rax = -1;
                    ptrace(PTRACE_SETREGS, pid, NULL, &regs);
                    kill(pid, SIGKILL);
                    break;
                }
            }
        }

        in_syscall ^= 1;
    }

    printf("[DEEP] ptrace detached from pid=%d\n", pid);
    fflush(stdout);
    return NULL;
}

/*
 * attach_ptrace_to_pid — spawns a dedicated thread to ptrace-watch a PID.
 * Called when a process is identified as suspicious by the process scanner.
 */
static void attach_ptrace_to_pid(unsigned long pid, const char* exe_path) {
    PtraceArgs* args = malloc(sizeof(PtraceArgs));
    if (!args) return;

    args->pid = pid;
    strncpy(args->exe_path, exe_path ? exe_path : "", PATH_MAX - 1);
    args->exe_path[PATH_MAX - 1] = '\0';

    pthread_t t;
    if (pthread_create(&t, NULL, ptrace_watch_process, args) != 0) {
        fprintf(stderr, "[DEEP] Failed to create ptrace thread for pid=%lu\n", pid);
        free(args);
        return;
    }
    pthread_detach(t);
}

/* ============================================================
 * SECTION 7: Process scanner
 * ============================================================
 * Same snapshot-diff approach as hips.c, but when a suspicious
 * new process is found, ptrace is attached for deep monitoring.
 * ============================================================ */

typedef struct {
    unsigned long pid;
    char          exe[PATH_MAX];
} ProcSnap;

static void* process_scanner_thread(void* arg) {
    (void)arg;

    static ProcSnap prev[MAX_PROCESSES];
    static int      prev_count = 0;

    static unsigned long watched_pids[MAX_WATCHED];
    static int           watched_count = 0;

    printf("[DEEP] Process scanner started\n");
    fflush(stdout);

    while (1) {
        ProcSnap current[MAX_PROCESSES];
        int current_count = 0;

        DIR* proc = opendir("/proc");
        if (!proc) { HP_SLEEP_MS(POLL_INTERVAL_MS); continue; }

        struct dirent* entry;
        while ((entry = readdir(proc)) != NULL && current_count < MAX_PROCESSES) {
            int is_pid = 1;
            for (int i = 0; entry->d_name[i]; i++)
                if (entry->d_name[i] < '0' || entry->d_name[i] > '9') { is_pid = 0; break; }
            if (!is_pid) continue;

            char pid_str[16];
            strncpy(pid_str, entry->d_name, sizeof(pid_str) - 1);
            pid_str[sizeof(pid_str) - 1] = '\0';

            current[current_count].pid = (unsigned long)atol(pid_str);

            char exe_link[64];
            snprintf(exe_link, sizeof(exe_link), "/proc/%s/exe", pid_str);
            ssize_t len = readlink(exe_link,
                                   current[current_count].exe,
                                   PATH_MAX - 1);
            if (len > 0)
                current[current_count].exe[len] = '\0';
            else
                current[current_count].exe[0] = '\0';

            current_count++;
        }
        closedir(proc);

        /* Diff: find new PIDs */
        for (int i = 0; i < current_count; i++) {
            unsigned long pid = current[i].pid;

            int is_new = 1;
            for (int j = 0; j < prev_count; j++) {
                if (prev[j].pid == pid) { is_new = 0; break; }
            }
            if (!is_new) continue;

            const char* exe = current[i].exe;

            if (exe[0] && is_suspicious_proc_path(exe)) {
                hp_alert(ALERT_HIGH, "scanner",
                    "New suspicious process | pid=%lu exe=%s", pid, exe);

                int already_watched = 0;
                for (int w = 0; w < watched_count; w++) {
                    if (watched_pids[w] == pid) { already_watched = 1; break; }
                }

                if (!already_watched && watched_count < MAX_WATCHED) {
                    attach_ptrace_to_pid(pid, exe);
                    watched_pids[watched_count++] = pid;

                    hp_alert(ALERT_HIGH, "scanner",
                        "ptrace attached to pid=%lu — full syscall monitoring active", pid);
                }
            } else {
                hp_alert(ALERT_LOW, "scanner",
                    "New process | pid=%lu exe=%s",
                    pid, exe[0] ? exe : "unknown");
            }
        }

        prev_count = current_count;
        memcpy(prev, current, current_count * sizeof(ProcSnap));

        HP_SLEEP_MS(POLL_INTERVAL_MS);
    }
    return NULL;
}

/* ============================================================
 * SECTION 8: main()
 * ============================================================
 * Three threads:
 *   1. passive_monitor_thread — reads /proc/PID/syscall passively
 *   2. process_scanner_thread — finds new processes, attaches ptrace to suspicious ones
 *   3. ptrace threads         — spawned dynamically per suspicious process
 * ============================================================ */

int main(void) {
    printf("[DEEP] hips_deep starting...\n");
    printf("[DEEP] Note: ptrace attachment requires root for non-child processes\n");
    printf("[DEEP] Run with: sudo ./hips_deep\n\n");
    fflush(stdout);

    pthread_t t_passive, t_scanner;

    if (pthread_create(&t_passive, NULL, passive_monitor_thread, NULL) != 0) {
        fprintf(stderr, "[DEEP] Failed to start passive monitor\n");
        return 1;
    }

    if (pthread_create(&t_scanner, NULL, process_scanner_thread, NULL) != 0) {
        fprintf(stderr, "[DEEP] Failed to start process scanner\n");
        return 1;
    }

    pthread_detach(t_passive);
    pthread_detach(t_scanner);

    printf("[DEEP] Running. Press 'q' + Enter to stop.\n");
    fflush(stdout);

    char c;
    do { c = (char)getchar(); } while (c != 'q');

    printf("[DEEP] Shutting down.\n");
    return 0;
}
