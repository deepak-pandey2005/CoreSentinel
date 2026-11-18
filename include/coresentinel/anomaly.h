#ifndef __CORESENTINEL_ANOMALY_H__
#define __CORESENTINEL_ANOMALY_H__

#include "coresentinel.h"
#include <pthread.h>
#include <stdint.h>
#include <stdbool.h>

#define MAX_RECENT_EXECS   50
#define MAX_RECENT_CONNS   50
#define MAX_RECENT_ALERTS  50
#define MAX_RECENT_FILES   50

typedef struct {
    uint64_t total_events;
    uint64_t total_execs;
    uint64_t total_connects;
    uint64_t total_file_opens;
    uint64_t total_priv_esc;
    uint64_t total_alerts;

    uint64_t alerts_by_sev[5]; /* 0: info, 1: low, 2: medium, 3: high, 4: critical */

    struct sentinel_event recent_execs[MAX_RECENT_EXECS];
    int exec_head;
    int exec_count;

    struct sentinel_event recent_conns[MAX_RECENT_CONNS];
    int conn_head;
    int conn_count;

    struct sentinel_event recent_alerts[MAX_RECENT_ALERTS];
    int alert_head;
    int alert_count;

    struct sentinel_event recent_files[MAX_RECENT_FILES];
    int file_head;
    int file_count;

    pthread_mutex_t lock;
} anomaly_state_t;

anomaly_state_t* anomaly_state_init(void);
void anomaly_state_free(anomaly_state_t *st);

void anomaly_record_event(anomaly_state_t *st, const struct sentinel_event *e);

const char* sentinel_severity_str(unsigned int sev);
const char* sentinel_event_type_str(unsigned int type);

#endif /* __CORESENTINEL_ANOMALY_H__ */
