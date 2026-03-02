/*
 * nullsec-poltergeist — /proc Anomaly Detector (C)
 * Part of the nullsec freakshow suite.
 *
 * Reads /proc directly to detect hidden processes, PID gaps,
 * and anomalous /proc entries that rootkits try to hide.
 *
 * Build: gcc -O2 -o poltergeist poltergeist.c
 * Usage: poltergeist [scan|pids|proc-check]
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <ctype.h>
#include <errno.h>
#include <time.h>

#define VERSION "1.0.0"
#define MAX_PIDS 65536

typedef struct {
    pid_t pid;
    char comm[256];
    char state;
    uid_t uid;
    int hidden;       /* 1 if found via brute-force but not readdir */
    int suspicious;
    char reason[256];
} proc_info_t;

static int is_numeric(const char *s) {
    while (*s) {
        if (!isdigit(*s)) return 0;
        s++;
    }
    return 1;
}

static int read_proc_comm(pid_t pid, char *buf, size_t len) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/comm", pid);
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    if (fgets(buf, len, f)) {
        buf[strcspn(buf, "\n")] = 0;
    }
    fclose(f);
    return 0;
}

static int read_proc_status_uid(pid_t pid, uid_t *uid) {
    char path[64], line[512];
    snprintf(path, sizeof(path), "/proc/%d/status", pid);
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "Uid:", 4) == 0) {
            *uid = (uid_t)atoi(line + 5);
            fclose(f);
            return 0;
        }
    }
    fclose(f);
    return -1;
}

static char read_proc_state(pid_t pid) {
    char path[64], line[512];
    snprintf(path, sizeof(path), "/proc/%d/stat", pid);
    FILE *f = fopen(path, "r");
    if (!f) return '?';
    if (fgets(line, sizeof(line), f)) {
        /* Format: pid (comm) state ... */
        char *p = strrchr(line, ')');
        if (p && *(p+1) == ' ') {
            fclose(f);
            return *(p+2);
        }
    }
    fclose(f);
    return '?';
}

static int check_proc_exe_deleted(pid_t pid) {
    char path[64], link[512];
    snprintf(path, sizeof(path), "/proc/%d/exe", pid);
    ssize_t len = readlink(path, link, sizeof(link) - 1);
    if (len > 0) {
        link[len] = 0;
        if (strstr(link, "(deleted)")) return 1;
    }
    return 0;
}

static int check_proc_maps_anomaly(pid_t pid) {
    char path[64], line[1024];
    snprintf(path, sizeof(path), "/proc/%d/maps", pid);
    FILE *f = fopen(path, "r");
    if (!f) return 0;
    int suspicious = 0;
    while (fgets(line, sizeof(line), f)) {
        /* rwxp with no backing file = anonymous executable mapping */
        if (strstr(line, "rwxp") && !strstr(line, "/") && !strstr(line, "[")) {
            suspicious = 1;
            break;
        }
    }
    fclose(f);
    return suspicious;
}

/* Scan /proc via readdir and record visible PIDs */
static int scan_readdir(int *visible, int max_pid) {
    DIR *d = opendir("/proc");
    if (!d) {
        perror("Cannot open /proc");
        return -1;
    }
    struct dirent *entry;
    int count = 0;
    while ((entry = readdir(d)) != NULL) {
        if (is_numeric(entry->d_name)) {
            int pid = atoi(entry->d_name);
            if (pid > 0 && pid < max_pid) {
                visible[pid] = 1;
                count++;
            }
        }
    }
    closedir(d);
    return count;
}

/* Brute-force check PIDs by accessing /proc/<pid>/comm directly */
static int scan_bruteforce(int *exists, int max_pid) {
    int count = 0;
    for (int pid = 1; pid < max_pid; pid++) {
        char path[64];
        snprintf(path, sizeof(path), "/proc/%d", pid);
        struct stat st;
        if (stat(path, &st) == 0) {
            exists[pid] = 1;
            count++;
        }
    }
    return count;
}

static void cmd_scan(void) {
    printf("\n👻 POLTERGEIST — /proc Anomaly Detector\n\n");

    time_t now = time(NULL);
    printf("  Scan time: %s", ctime(&now));

    int visible[MAX_PIDS] = {0};
    int exists[MAX_PIDS] = {0};

    int vis_count = scan_readdir(visible, MAX_PIDS);
    int brute_count = scan_bruteforce(exists, MAX_PIDS);

    printf("  Visible via readdir:   %d\n", vis_count);
    printf("  Found via brute-force: %d\n\n", brute_count);

    int hidden = 0;
    int suspicious = 0;
    int deleted_exe = 0;
    int anon_rwx = 0;

    for (int pid = 1; pid < MAX_PIDS; pid++) {
        if (exists[pid] && !visible[pid]) {
            hidden++;
            char comm[256] = "???";
            read_proc_comm(pid, comm, sizeof(comm));
            printf("  🔴 HIDDEN PID %d (%s) — not visible in readdir!\n", pid, comm);
        }
    }

    /* Check for suspicious traits on all visible processes */
    for (int pid = 1; pid < MAX_PIDS; pid++) {
        if (!visible[pid]) continue;

        if (check_proc_exe_deleted(pid)) {
            char comm[256] = "???";
            read_proc_comm(pid, comm, sizeof(comm));
            printf("  🟡 PID %d (%s) — executable DELETED from disk\n", pid, comm);
            deleted_exe++;
        }

        if (check_proc_maps_anomaly(pid)) {
            char comm[256] = "???";
            read_proc_comm(pid, comm, sizeof(comm));
            printf("  🟡 PID %d (%s) — anonymous RWX memory mapping\n", pid, comm);
            anon_rwx++;
            suspicious++;
        }
    }

    printf("\n  ──────────────────────────────\n");
    printf("  👻 %d hidden, %d deleted-exe, %d anon-RWX\n", hidden, deleted_exe, anon_rwx);

    if (hidden == 0 && suspicious == 0) {
        printf("  ✅ No anomalies — the poltergeist found nothing.\n");
    }
    printf("\n");
}

static void cmd_pids(void) {
    printf("\n👻 POLTERGEIST — PID Listing\n\n");
    printf("  %-8s %-20s %-6s %-8s\n", "PID", "COMMAND", "STATE", "UID");
    printf("  %-8s %-20s %-6s %-8s\n", "---", "-------", "-----", "---");

    DIR *d = opendir("/proc");
    if (!d) { perror("/proc"); return; }

    struct dirent *entry;
    while ((entry = readdir(d)) != NULL) {
        if (!is_numeric(entry->d_name)) continue;
        pid_t pid = atoi(entry->d_name);
        char comm[256] = "???";
        uid_t uid = 0;
        char state = read_proc_state(pid);
        read_proc_comm(pid, comm, sizeof(comm));
        read_proc_status_uid(pid, &uid);
        printf("  %-8d %-20s %-6c %-8d\n", pid, comm, state, uid);
    }
    closedir(d);
    printf("\n");
}

static void print_help(void) {
    printf("\n👻 nullsec-poltergeist v%s — /proc Anomaly Detector (C)\n", VERSION);
    printf("   Part of the nullsec freakshow suite.\n\n");
    printf("Usage:\n");
    printf("  poltergeist scan         Full anomaly scan (hidden PIDs, deleted exes, RWX)\n");
    printf("  poltergeist pids         List all visible processes\n");
    printf("  poltergeist --help       This help\n\n");
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        print_help();
        return 0;
    }

    if (strcmp(argv[1], "scan") == 0) {
        cmd_scan();
    } else if (strcmp(argv[1], "pids") == 0) {
        cmd_pids();
    } else if (strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "-h") == 0) {
        print_help();
    } else {
        print_help();
    }

    return 0;
}
