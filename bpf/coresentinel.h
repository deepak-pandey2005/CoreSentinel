#ifndef __CORESENTINEL_H__
#define __CORESENTINEL_H__

#define TASK_COMM_LEN 16
#define MAX_PATH_LEN  256
#define MAX_ALERT_LEN 128

enum event_type {
    EVENT_UNKNOWN   = 0,
    EVENT_EXEC      = 1,
    EVENT_CONNECT   = 2,
    EVENT_ACCEPT    = 3,
    EVENT_FILE_OPEN = 4,
    EVENT_PRIV_ESC  = 5,
};

enum sentinel_severity {
    SENTINEL_SEV_INFO     = 0,
    SENTINEL_SEV_LOW      = 1,
    SENTINEL_SEV_MEDIUM   = 2,
    SENTINEL_SEV_HIGH     = 3,
    SENTINEL_SEV_CRITICAL = 4,
};

struct sentinel_event {
    unsigned long long timestamp_ns;
    unsigned int event_type;
    unsigned int severity;
    unsigned int pid;
    unsigned int tid;
    unsigned int ppid;
    unsigned int uid;
    unsigned int gid;
    unsigned int old_uid;

    char comm[TASK_COMM_LEN];
    char pcomm[TASK_COMM_LEN];

    /* Process execution fields */
    char filename[MAX_PATH_LEN];
    int is_suspicious_path;

    /* Network socket fields */
    unsigned int saddr;
    unsigned int daddr;
    unsigned short sport;
    unsigned short dport;
    unsigned short family;
    unsigned short proto;

    /* File integrity fields */
    char file_path[MAX_PATH_LEN];
    unsigned int open_flags;
    int is_write_access;
    int is_sensitive_file;

    /* Anomaly / Alert message */
    char alert_msg[MAX_ALERT_LEN];
};

#endif /* __CORESENTINEL_H__ */
