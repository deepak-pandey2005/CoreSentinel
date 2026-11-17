#include "coresentinel/engine.h"
#include "coresentinel.skel.h"
#include <bpf/libbpf.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

struct coresentinel_engine {
    coresentinel_config_t cfg;
    anomaly_state_t *state;
    struct coresentinel_bpf *skel;
    struct ring_buffer *rb;
    FILE *log_fp;
    volatile bool running;
};

static int handle_event(void *ctx, void *data, size_t data_sz) {
    coresentinel_engine_t *eng = (coresentinel_engine_t*)ctx;
    if (data_sz < sizeof(struct sentinel_event)) {
        return 0;
    }

    const struct sentinel_event *e = (const struct sentinel_event*)data;
    anomaly_record_event(eng->state, e);

    if (eng->log_fp) {
        time_t sec = (time_t)(e->timestamp_ns / 1000000000ULL);
        struct tm tm_info;
        localtime_r(&sec, &tm_info);
        char time_str[32];
        strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", &tm_info);

        fprintf(eng->log_fp, "[%s] [%s] [%s] PID=%u UID=%u COMM=%s ",
                time_str,
                sentinel_severity_str(e->severity),
                sentinel_event_type_str(e->event_type),
                e->pid, e->uid, e->comm);

        if (e->event_type == EVENT_EXEC) {
            fprintf(eng->log_fp, "FILE=%s PARENT=%s ", e->filename, e->pcomm);
        } else if (e->event_type == EVENT_FILE_OPEN) {
            fprintf(eng->log_fp, "PATH=%s WRITE=%d ", e->file_path, e->is_write_access);
        } else if (e->event_type == EVENT_CONNECT) {
            fprintf(eng->log_fp, "DEST_PORT=%u ", e->dport);
        }

        if (e->alert_msg[0]) {
            fprintf(eng->log_fp, "ALERT=\"%s\" ", e->alert_msg);
        }
        fprintf(eng->log_fp, "\n");
        fflush(eng->log_fp);
    }

    return 0;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args) {
    if (level == LIBBPF_DEBUG)
        return 0;
    return vfprintf(stderr, format, args);
}

coresentinel_engine_t* coresentinel_engine_create(const coresentinel_config_t *cfg, anomaly_state_t *state) {
    if (!cfg || !state) return NULL;

    coresentinel_engine_t *eng = (coresentinel_engine_t*)calloc(1, sizeof(coresentinel_engine_t));
    if (!eng) return NULL;

    eng->cfg = *cfg;
    eng->state = state;
    eng->running = false;

    if (cfg->log_file[0] != '\0') {
        eng->log_fp = fopen(cfg->log_file, "a");
    }

    libbpf_set_print(libbpf_print_fn);

    eng->skel = coresentinel_bpf__open_and_load();
    if (!eng->skel) {
        fprintf(stderr, "Failed to open and load eBPF skeleton: %s\n", strerror(errno));
        if (eng->log_fp) fclose(eng->log_fp);
        free(eng);
        return NULL;
    }

    int events_map_fd = bpf_map__fd(eng->skel->maps.events);
    eng->rb = ring_buffer__new(events_map_fd, handle_event, eng, NULL);
    if (!eng->rb) {
        fprintf(stderr, "Failed to create eBPF ring buffer: %s\n", strerror(errno));
        coresentinel_bpf__destroy(eng->skel);
        if (eng->log_fp) fclose(eng->log_fp);
        free(eng);
        return NULL;
    }

    return eng;
}

int coresentinel_engine_start(coresentinel_engine_t *eng) {
    if (!eng || !eng->skel) return -1;

    int err = coresentinel_bpf__attach(eng->skel);
    if (err) {
        fprintf(stderr, "Failed to attach eBPF programs: %d\n", err);
        return err;
    }

    eng->running = true;
    return 0;
}

int coresentinel_engine_poll(coresentinel_engine_t *eng, int timeout_ms) {
    if (!eng || !eng->rb || !eng->running) return -1;
    return ring_buffer__poll(eng->rb, timeout_ms);
}

void coresentinel_engine_stop(coresentinel_engine_t *eng) {
    if (!eng) return;
    eng->running = false;
}

void coresentinel_engine_destroy(coresentinel_engine_t *eng) {
    if (!eng) return;
    eng->running = false;
    if (eng->rb) {
        ring_buffer__free(eng->rb);
        eng->rb = NULL;
    }
    if (eng->skel) {
        coresentinel_bpf__destroy(eng->skel);
        eng->skel = NULL;
    }
    if (eng->log_fp) {
        fclose(eng->log_fp);
        eng->log_fp = NULL;
    }
    free(eng);
}
