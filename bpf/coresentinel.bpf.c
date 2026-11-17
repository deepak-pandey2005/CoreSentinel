#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>
#include "coresentinel.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024); /* 256 KB */
} events SEC(".maps");

/* Helper to compare string prefixes in BPF */
static __always_inline int has_prefix(const char *str, const char *prefix, int n) {
    for (int i = 0; i < n; i++) {
        if (str[i] != prefix[i])
            return 0;
        if (prefix[i] == '\0')
            return 1;
    }
    return 1;
}

static __always_inline int is_suspicious_binary_path(const char *path) {
    if (has_prefix(path, "/tmp/", 5)) return 1;
    if (has_prefix(path, "/dev/shm/", 9)) return 1;
    if (has_prefix(path, "/var/tmp/", 9)) return 1;
    if (has_prefix(path, "/run/user/", 10)) return 1;
    return 0;
}

static __always_inline int is_sensitive_file_path(const char *path) {
    if (has_prefix(path, "/etc/shadow", 11)) return 1;
    if (has_prefix(path, "/etc/passwd", 11)) return 1;
    if (has_prefix(path, "/etc/sudoers", 12)) return 1;
    if (has_prefix(path, "/etc/ld.so.preload", 18)) return 1;
    if (has_prefix(path, "/etc/pam.d/", 11)) return 1;
    return 0;
}

/* 1. Process Execution Monitoring */
SEC("tracepoint/syscalls/sys_enter_execve")
int trace_sys_enter_execve(struct trace_event_raw_sys_enter *ctx) {
    struct sentinel_event *e;
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;

    __builtin_memset(e, 0, sizeof(*e));
    e->timestamp_ns = bpf_ktime_get_ns();
    e->event_type = EVENT_EXEC;
    e->severity = SENTINEL_SEV_INFO;

    unsigned long long pid_tgid = bpf_get_current_pid_tgid();
    e->pid = pid_tgid >> 32;
    e->tid = (unsigned int)pid_tgid;

    unsigned long long uid_gid = bpf_get_current_uid_gid();
    e->uid = (unsigned int)uid_gid;
    e->gid = uid_gid >> 32;

    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();
    if (task) {
        struct task_struct *parent = BPF_CORE_READ(task, real_parent);
        if (parent) {
            e->ppid = BPF_CORE_READ(parent, tgid);
            BPF_CORE_READ_STR_INTO(&e->pcomm, parent, comm);
        }
    }

    const char *filename_ptr = (const char *)ctx->args[0];
    if (filename_ptr) {
        bpf_probe_read_user_str(&e->filename, sizeof(e->filename), filename_ptr);
    }

    /* Safety rule: Binary executed from volatile/world-writable directory */
    if (is_suspicious_binary_path(e->filename)) {
        e->is_suspicious_path = 1;
        e->severity = SENTINEL_SEV_HIGH;
        __builtin_memcpy(e->alert_msg, "Suspicious binary executed from writable/temp directory", 56);
    }

    /* Safety rule: Potential reverse shell spawn from web servers or script runtimes */
    if ((has_prefix(e->pcomm, "nginx", 5) || has_prefix(e->pcomm, "apache", 6) ||
         has_prefix(e->pcomm, "httpd", 5) || has_prefix(e->pcomm, "node", 4) ||
         has_prefix(e->pcomm, "python", 6) || has_prefix(e->pcomm, "nc", 2)) &&
        (has_prefix(e->comm, "sh", 2) || has_prefix(e->comm, "bash", 4) ||
         has_prefix(e->comm, "dash", 4) || has_prefix(e->comm, "zsh", 3))) {
        e->severity = SENTINEL_SEV_CRITICAL;
        __builtin_memcpy(e->alert_msg, "Potential reverse shell: interactive shell spawned by network/script daemon", 76);
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* 2. Privilege Escalation Monitoring */
SEC("tracepoint/syscalls/sys_enter_setuid")
int trace_sys_enter_setuid(struct trace_event_raw_sys_enter *ctx) {
    unsigned int target_uid = (unsigned int)ctx->args[0];
    unsigned long long uid_gid = bpf_get_current_uid_gid();
    unsigned int current_uid = (unsigned int)uid_gid;

    /* If changing to root from a non-root caller, report */
    if (current_uid != 0 && target_uid == 0) {
        struct sentinel_event *e;
        e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
        if (!e) return 0;

        __builtin_memset(e, 0, sizeof(*e));
        e->timestamp_ns = bpf_ktime_get_ns();
        e->event_type = EVENT_PRIV_ESC;
        e->severity = SENTINEL_SEV_CRITICAL;

        unsigned long long pid_tgid = bpf_get_current_pid_tgid();
        e->pid = pid_tgid >> 32;
        e->tid = (unsigned int)pid_tgid;
        e->uid = target_uid;
        e->old_uid = current_uid;
        e->gid = uid_gid >> 32;

        bpf_get_current_comm(&e->comm, sizeof(e->comm));
        __builtin_memcpy(e->alert_msg, "Privilege escalation: non-root user transitioned to UID 0 (root)", 65);

        bpf_ringbuf_submit(e, 0);
    }
    return 0;
}

/* 3. Sensitive File Access & Integrity Monitoring */
SEC("tracepoint/syscalls/sys_enter_openat")
int trace_sys_enter_openat(struct trace_event_raw_sys_enter *ctx) {
    const char *file_ptr = (const char *)ctx->args[1];
    if (!file_ptr) return 0;

    char test_path[64];
    __builtin_memset(test_path, 0, sizeof(test_path));
    long ret = bpf_probe_read_user_str(test_path, sizeof(test_path), file_ptr);
    if (ret <= 0) return 0;

    if (!is_sensitive_file_path(test_path)) {
        return 0;
    }

    struct sentinel_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;

    __builtin_memset(e, 0, sizeof(*e));
    e->timestamp_ns = bpf_ktime_get_ns();
    e->event_type = EVENT_FILE_OPEN;
    e->severity = SENTINEL_SEV_MEDIUM;
    e->is_sensitive_file = 1;

    unsigned long long pid_tgid = bpf_get_current_pid_tgid();
    e->pid = pid_tgid >> 32;
    e->tid = (unsigned int)pid_tgid;

    unsigned long long uid_gid = bpf_get_current_uid_gid();
    e->uid = (unsigned int)uid_gid;
    e->gid = uid_gid >> 32;

    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    bpf_probe_read_user_str(&e->file_path, sizeof(e->file_path), file_ptr);
    e->open_flags = (unsigned int)ctx->args[2];

    /* Check if write/create/truncate flags set (01 = O_WRONLY, 02 = O_RDWR, 0100 = O_CREAT, 01000 = O_TRUNC) */
    if ((e->open_flags & 0x01) || (e->open_flags & 0x02) || (e->open_flags & 0x200)) {
        e->is_write_access = 1;
        e->severity = SENTINEL_SEV_CRITICAL;
        __builtin_memcpy(e->alert_msg, "CRITICAL: Write/modification attempt on protected system file", 62);
    } else {
        e->severity = SENTINEL_SEV_MEDIUM;
        __builtin_memcpy(e->alert_msg, "Sensitive credential/system file read access", 45);
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* 4. Network Socket Outbound Connections */
SEC("tracepoint/syscalls/sys_enter_connect")
int trace_sys_enter_connect(struct trace_event_raw_sys_enter *ctx) {
    struct sockaddr *sock_addr = (struct sockaddr *)ctx->args[1];
    if (!sock_addr) return 0;

    unsigned short family = 0;
    if (bpf_probe_read_user(&family, sizeof(family), &sock_addr->sa_family) != 0) {
        return 0;
    }

    /* Filter IPv4 (AF_INET = 2) */
    if (family != 2) return 0;

    struct sockaddr_in in4;
    __builtin_memset(&in4, 0, sizeof(in4));
    if (bpf_probe_read_user(&in4, sizeof(in4), sock_addr) != 0) {
        return 0;
    }

    struct sentinel_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;

    __builtin_memset(e, 0, sizeof(*e));
    e->timestamp_ns = bpf_ktime_get_ns();
    e->event_type = EVENT_CONNECT;
    e->severity = SENTINEL_SEV_INFO;

    unsigned long long pid_tgid = bpf_get_current_pid_tgid();
    e->pid = pid_tgid >> 32;
    e->tid = (unsigned int)pid_tgid;

    unsigned long long uid_gid = bpf_get_current_uid_gid();
    e->uid = (unsigned int)uid_gid;
    e->gid = uid_gid >> 32;

    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    e->family = family;
    e->proto = 6; /* IPPROTO_TCP */
    e->daddr = in4.sin_addr.s_addr;
    e->dport = __builtin_bswap16(in4.sin_port);

    /* Heuristic rule: Unusual or high-risk outbound ports */
    if (e->dport == 4444 || e->dport == 1337 || e->dport == 31337 || e->dport == 6667) {
        e->severity = SENTINEL_SEV_HIGH;
        __builtin_memcpy(e->alert_msg, "Outbound connection to known C2 / hacker backdoor port", 55);
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}
