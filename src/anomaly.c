#include "coresentinel/anomaly.h"
#include <stdlib.h>
#include <string.h>

anomaly_state_t* anomaly_state_init(void) {
    anomaly_state_t *st = (anomaly_state_t*)calloc(1, sizeof(anomaly_state_t));
    if (!st) return NULL;
    pthread_mutex_init(&st->lock, NULL);
    return st;
}

void anomaly_state_free(anomaly_state_t *st) {
    if (!st) return;
    pthread_mutex_destroy(&st->lock);
    free(st);
}

void anomaly_record_event(anomaly_state_t *st, const struct sentinel_event *e) {
    if (!st || !e) return;

    pthread_mutex_lock(&st->lock);

    st->total_events++;
    if (e->severity < 5) {
        st->alerts_by_sev[e->severity]++;
    }

    if (e->severity >= SENTINEL_SEV_MEDIUM) {
        st->total_alerts++;
        int slot = st->alert_head;
        st->recent_alerts[slot] = *e;
        st->alert_head = (slot + 1) % MAX_RECENT_ALERTS;
        if (st->alert_count < MAX_RECENT_ALERTS) st->alert_count++;
    }

    switch (e->event_type) {
        case EVENT_EXEC: {
            st->total_execs++;
            int slot = st->exec_head;
            st->recent_execs[slot] = *e;
            st->exec_head = (slot + 1) % MAX_RECENT_EXECS;
            if (st->exec_count < MAX_RECENT_EXECS) st->exec_count++;
            break;
        }
        case EVENT_CONNECT: {
            st->total_connects++;
            int slot = st->conn_head;
            st->recent_conns[slot] = *e;
            st->conn_head = (slot + 1) % MAX_RECENT_CONNS;
            if (st->conn_count < MAX_RECENT_CONNS) st->conn_count++;
            break;
        }
        case EVENT_FILE_OPEN: {
            st->total_file_opens++;
            int slot = st->file_head;
            st->recent_files[slot] = *e;
            st->file_head = (slot + 1) % MAX_RECENT_FILES;
            if (st->file_count < MAX_RECENT_FILES) st->file_count++;
            break;
        }
        case EVENT_PRIV_ESC: {
            st->total_priv_esc++;
            break;
        }
        default:
            break;
    }

    pthread_mutex_unlock(&st->lock);
}

const char* sentinel_severity_str(unsigned int sev) {
    switch (sev) {
        case SENTINEL_SEV_INFO:     return "INFO";
        case SENTINEL_SEV_LOW:      return "LOW";
        case SENTINEL_SEV_MEDIUM:   return "MEDIUM";
        case SENTINEL_SEV_HIGH:     return "HIGH";
        case SENTINEL_SEV_CRITICAL: return "CRITICAL";
        default:                    return "UNKNOWN";
    }
}

const char* sentinel_event_type_str(unsigned int type) {
    switch (type) {
        case EVENT_EXEC:      return "EXEC";
        case EVENT_CONNECT:   return "CONNECT";
        case EVENT_ACCEPT:    return "ACCEPT";
        case EVENT_FILE_OPEN: return "FILE_OPEN";
        case EVENT_PRIV_ESC:  return "PRIV_ESC";
        default:              return "OTHER";
    }
}
