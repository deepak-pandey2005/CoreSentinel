#include "coresentinel/metrics.h"
#include <arpa/inet.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

struct metrics_server {
    int server_fd;
    int port;
    anomaly_state_t *state;
    pthread_t thread;
    volatile bool running;
};

static void send_response(int client_fd, const char *status, const char *body) {
    char response[8192];
    int body_len = (int)strlen(body);
    int total_len = snprintf(response, sizeof(response),
                             "HTTP/1.1 %s\r\n"
                             "Content-Type: text/plain; version=0.0.4; charset=utf-8\r\n"
                             "Content-Length: %d\r\n"
                             "Connection: close\r\n\r\n"
                             "%s",
                             status, body_len, body);
    if (total_len > 0) {
        ssize_t sent = 0;
        while (sent < total_len) {
            ssize_t res = write(client_fd, response + sent, total_len - sent);
            if (res <= 0) break;
            sent += res;
        }
    }
}

static void* metrics_worker(void *arg) {
    metrics_server_t *srv = (metrics_server_t*)arg;
    char buffer[1024];

    while (srv->running) {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        int client_fd = accept(srv->server_fd, (struct sockaddr*)&client_addr, &client_len);
        if (client_fd < 0) {
            if (!srv->running) break;
            continue;
        }

        memset(buffer, 0, sizeof(buffer));
        ssize_t n = read(client_fd, buffer, sizeof(buffer) - 1);
        if (n > 0) {
            if (strstr(buffer, "GET /healthz") == buffer) {
                send_response(client_fd, "200 OK", "OK\n");
            } else if (strstr(buffer, "GET /metrics") == buffer || strstr(buffer, "GET / ") == buffer) {
                char body[4096];
                int offset = 0;

                pthread_mutex_lock(&srv->state->lock);
                uint64_t tot_events = srv->state->total_events;
                uint64_t tot_execs = srv->state->total_execs;
                uint64_t tot_conns = srv->state->total_connects;
                uint64_t tot_files = srv->state->total_file_opens;
                uint64_t tot_priv = srv->state->total_priv_esc;
                uint64_t tot_alerts = srv->state->total_alerts;
                uint64_t sev_counts[5];
                memcpy(sev_counts, srv->state->alerts_by_sev, sizeof(sev_counts));
                pthread_mutex_unlock(&srv->state->lock);

                offset += snprintf(body + offset, sizeof(body) - offset,
                    "# HELP coresentinel_events_total Total eBPF kernel security and observation events\n"
                    "# TYPE coresentinel_events_total counter\n"
                    "coresentinel_events_total %llu\n\n"
                    "# HELP coresentinel_exec_events_total Total process execution events\n"
                    "# TYPE coresentinel_exec_events_total counter\n"
                    "coresentinel_exec_events_total %llu\n\n"
                    "# HELP coresentinel_connect_events_total Total outbound socket connect events\n"
                    "# TYPE coresentinel_connect_events_total counter\n"
                    "coresentinel_connect_events_total %llu\n\n"
                    "# HELP coresentinel_file_open_events_total Total sensitive file open events\n"
                    "# TYPE coresentinel_file_open_events_total counter\n"
                    "coresentinel_file_open_events_total %llu\n\n"
                    "# HELP coresentinel_priv_esc_events_total Total privilege escalation events\n"
                    "# TYPE coresentinel_priv_esc_events_total counter\n"
                    "coresentinel_priv_esc_events_total %llu\n\n"
                    "# HELP coresentinel_alerts_total Total security anomaly alerts detected\n"
                    "# TYPE coresentinel_alerts_total counter\n"
                    "coresentinel_alerts_total %llu\n"
                    "coresentinel_alerts_total{severity=\"info\"} %llu\n"
                    "coresentinel_alerts_total{severity=\"low\"} %llu\n"
                    "coresentinel_alerts_total{severity=\"medium\"} %llu\n"
                    "coresentinel_alerts_total{severity=\"high\"} %llu\n"
                    "coresentinel_alerts_total{severity=\"critical\"} %llu\n",
                    (unsigned long long)tot_events,
                    (unsigned long long)tot_execs,
                    (unsigned long long)tot_conns,
                    (unsigned long long)tot_files,
                    (unsigned long long)tot_priv,
                    (unsigned long long)tot_alerts,
                    (unsigned long long)sev_counts[0],
                    (unsigned long long)sev_counts[1],
                    (unsigned long long)sev_counts[2],
                    (unsigned long long)sev_counts[3],
                    (unsigned long long)sev_counts[4]);

                send_response(client_fd, "200 OK", body);
            } else {
                send_response(client_fd, "404 Not Found", "Not Found\n");
            }
        }
        close(client_fd);
    }
    return NULL;
}

metrics_server_t* metrics_server_start(int port, anomaly_state_t *anomaly_state) {
    if (port <= 0 || !anomaly_state) return NULL;

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return NULL;

    int opt = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons((uint16_t)port);

    if (bind(fd, (struct sockaddr*)&addr, sizeof(addr)) != 0) {
        close(fd);
        return NULL;
    }

    if (listen(fd, 16) != 0) {
        close(fd);
        return NULL;
    }

    metrics_server_t *srv = (metrics_server_t*)calloc(1, sizeof(metrics_server_t));
    if (!srv) {
        close(fd);
        return NULL;
    }

    srv->server_fd = fd;
    srv->port = port;
    srv->state = anomaly_state;
    srv->running = true;

    if (pthread_create(&srv->thread, NULL, metrics_worker, srv) != 0) {
        close(fd);
        free(srv);
        return NULL;
    }

    return srv;
}

void metrics_server_stop(metrics_server_t *srv) {
    if (!srv) return;
    srv->running = false;
    shutdown(srv->server_fd, SHUT_RDWR);
    close(srv->server_fd);
    pthread_join(srv->thread, NULL);
    free(srv);
}
