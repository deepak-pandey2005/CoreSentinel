#include "coresentinel/tui.h"
#include <arpa/inet.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define ANSI_CLEAR       "\033[H\033[J"
#define ANSI_RESET       "\033[0m"
#define ANSI_BOLD        "\033[1m"
#define ANSI_CYAN        "\033[36m"
#define ANSI_GREEN       "\033[32m"
#define ANSI_YELLOW      "\033[33m"
#define ANSI_RED         "\033[31m"
#define ANSI_MAGENTA     "\033[35m"
#define ANSI_WHITE       "\033[37m"
#define ANSI_GRAY        "\033[90m"
#define ANSI_BG_RED      "\033[41;37m"
#define ANSI_BG_YELLOW   "\033[43;30m"

struct tui_dashboard {
    anomaly_state_t *state;
    int metrics_port;
    pthread_t thread;
    volatile bool running;
    time_t start_time;
};

static const char* format_ip(uint32_t ip, char *buf, size_t buflen) {
    struct in_addr in;
    in.s_addr = ip;
    inet_ntop(AF_INET, &in, buf, buflen);
    return buf;
}

static inline const char* e_status_safe(int is_suspicious) {
    if (is_suspicious) {
        return ANSI_BG_RED " SUSPICIOUS " ANSI_RESET;
    }
    return ANSI_GREEN " VERIFIED   " ANSI_RESET;
}

static void* tui_render_loop(void *arg) {
    tui_dashboard_t *tui = (tui_dashboard_t*)arg;

    // Hide cursor
    printf("\033[?25l");
    fflush(stdout);

    while (tui->running) {
        time_t now = time(NULL);
        long uptime = (long)(now - tui->start_time);
        int up_h = (int)(uptime / 3600);
        int up_m = (int)((uptime % 3600) / 60);
        int up_s = (int)(uptime % 60);

        pthread_mutex_lock(&tui->state->lock);
        uint64_t tot_events = tui->state->total_events;
        uint64_t tot_execs = tui->state->total_execs;
        uint64_t tot_conns = tui->state->total_connects;
        uint64_t tot_files = tui->state->total_file_opens;
        uint64_t tot_alerts = tui->state->total_alerts;

        int num_execs = tui->state->exec_count;
        struct sentinel_event execs_copy[MAX_RECENT_EXECS];
        for (int i = 0; i < num_execs; i++) {
            int idx = (tui->state->exec_head - 1 - i + MAX_RECENT_EXECS) % MAX_RECENT_EXECS;
            execs_copy[i] = tui->state->recent_execs[idx];
        }

        int num_conns = tui->state->conn_count;
        struct sentinel_event conns_copy[MAX_RECENT_CONNS];
        for (int i = 0; i < num_conns; i++) {
            int idx = (tui->state->conn_head - 1 - i + MAX_RECENT_CONNS) % MAX_RECENT_CONNS;
            conns_copy[i] = tui->state->recent_conns[idx];
        }

        int num_alerts = tui->state->alert_count;
        struct sentinel_event alerts_copy[MAX_RECENT_ALERTS];
        for (int i = 0; i < num_alerts; i++) {
            int idx = (tui->state->alert_head - 1 - i + MAX_RECENT_ALERTS) % MAX_RECENT_ALERTS;
            alerts_copy[i] = tui->state->recent_alerts[idx];
        }
        pthread_mutex_unlock(&tui->state->lock);

        // Render Frame
        printf("%s", ANSI_CLEAR);
        printf("%s%s╔═══════════════════════════════════════════════════════════════════════════════════════╗%s\n", ANSI_BOLD, ANSI_CYAN, ANSI_RESET);
        printf("%s%s║  CoreSentinel: eBPF Linux Kernel Security & Observability Engine (CO-RE)     ║%s\n", ANSI_BOLD, ANSI_CYAN, ANSI_RESET);
        printf("%s%s║  Kernel: %s● LIVE%s | Uptime: %02d:%02d:%02d | Prometheus: http://127.0.0.1:%-5d           ║%s\n",
               ANSI_BOLD, ANSI_CYAN, ANSI_GREEN, ANSI_CYAN, up_h, up_m, up_s, tui->metrics_port, ANSI_RESET);
        printf("%s%s║  Events: %-8llu | Execs: %-6llu | Sockets: %-6llu | Files: %-5llu | Alerts: %-5llu ║%s\n",
               ANSI_BOLD, ANSI_CYAN,
               (unsigned long long)tot_events,
               (unsigned long long)tot_execs,
               (unsigned long long)tot_conns,
               (unsigned long long)tot_files,
               (unsigned long long)tot_alerts,
               ANSI_RESET);
        printf("%s%s╚═══════════════════════════════════════════════════════════════════════════════════════╝%s\n\n", ANSI_BOLD, ANSI_CYAN, ANSI_RESET);

        // Section 1: Recent Process Executions
        printf("%s%s[ PROCESS EXECUTION OBSERVABILITY ]%s\n", ANSI_BOLD, ANSI_WHITE, ANSI_RESET);
        printf("%s%-7s %-6s %-12s %-12s %-36s %-10s%s\n", ANSI_GRAY, "PID", "UID", "COMM", "PARENT", "BINARY PATH", "STATUS", ANSI_RESET);
        printf("%s-----------------------------------------------------------------------------------%s\n", ANSI_GRAY, ANSI_RESET);
        if (num_execs == 0) {
            printf("%s(Waiting for process exec events...)%s\n", ANSI_GRAY, ANSI_RESET);
        } else {
            int show = num_execs > 5 ? 5 : num_execs;
            for (int i = 0; i < show; i++) {
                const char *badge = e_status_safe(execs_copy[i].is_suspicious_path);
                char path_truncated[36];
                snprintf(path_truncated, sizeof(path_truncated), "%s", execs_copy[i].filename);
                printf("%-7u %-6u %-12s %-12s %-36s %s\n",
                       execs_copy[i].pid,
                       execs_copy[i].uid,
                       execs_copy[i].comm,
                       execs_copy[i].pcomm[0] ? execs_copy[i].pcomm : "-",
                       path_truncated,
                       badge);
            }
        }
        printf("\n");

        // Section 2: Outbound Network Sockets
        printf("%s%s[ NETWORK SOCKET OBSERVABILITY (TCP EGRESS) ]%s\n", ANSI_BOLD, ANSI_WHITE, ANSI_RESET);
        printf("%s%-7s %-6s %-12s %-24s %-8s %-12s%s\n", ANSI_GRAY, "PID", "UID", "COMM", "REMOTE ENDPOINT", "PROTO", "STATUS", ANSI_RESET);
        printf("%s-----------------------------------------------------------------------------------%s\n", ANSI_GRAY, ANSI_RESET);
        if (num_conns == 0) {
            printf("%s(Waiting for socket connection events...)%s\n", ANSI_GRAY, ANSI_RESET);
        } else {
            int show = num_conns > 5 ? 5 : num_conns;
            for (int i = 0; i < show; i++) {
                char ip_str[32];
                char ep_str[64];
                format_ip(conns_copy[i].daddr, ip_str, sizeof(ip_str));
                snprintf(ep_str, sizeof(ep_str), "%s:%u", ip_str, conns_copy[i].dport);
                const char *status = (conns_copy[i].severity >= SENTINEL_SEV_HIGH)
                    ? ANSI_RED "SUSPICIOUS" ANSI_RESET
                    : ANSI_GREEN "NORMAL" ANSI_RESET;

                printf("%-7u %-6u %-12s %-24s %-8s %s\n",
                       conns_copy[i].pid,
                       conns_copy[i].uid,
                       conns_copy[i].comm,
                       ep_str,
                       "TCP",
                       status);
            }
        }
        printf("\n");

        // Section 3: Safety & Security Alerts
        printf("%s%s[ ACTIVE DEFENSE & SAFETY ANOMALIES ]%s\n", ANSI_BOLD, ANSI_WHITE, ANSI_RESET);
        printf("%s%-10s %-7s %-12s %-50s%s\n", ANSI_GRAY, "SEVERITY", "PID", "COMM", "ALERT DETAILS", ANSI_RESET);
        printf("%s-----------------------------------------------------------------------------------%s\n", ANSI_GRAY, ANSI_RESET);
        if (num_alerts == 0) {
            printf("%s%s✔ No security anomalies detected. System operating within baseline.%s\n", ANSI_BOLD, ANSI_GREEN, ANSI_RESET);
        } else {
            int show = num_alerts > 6 ? 6 : num_alerts;
            for (int i = 0; i < show; i++) {
                const char *sev_tag;
                if (alerts_copy[i].severity == SENTINEL_SEV_CRITICAL) {
                    sev_tag = ANSI_BG_RED " CRITICAL " ANSI_RESET;
                } else if (alerts_copy[i].severity == SENTINEL_SEV_HIGH) {
                    sev_tag = ANSI_RED " HIGH     " ANSI_RESET;
                } else {
                    sev_tag = ANSI_YELLOW " MEDIUM   " ANSI_RESET;
                }

                printf("%-10s %-7u %-12s %-50s\n",
                       sev_tag,
                       alerts_copy[i].pid,
                       alerts_copy[i].comm,
                       alerts_copy[i].alert_msg);
            }
        }
        printf("\n%sPress Ctrl+C to stop CoreSentinel.%s\n", ANSI_GRAY, ANSI_RESET);
        fflush(stdout);

        usleep(300000); // 300ms refresh
    }

    // Restore cursor
    printf("\033[?25h\n");
    fflush(stdout);
    return NULL;
}

tui_dashboard_t* tui_start(anomaly_state_t *state, int metrics_port) {
    if (!state) return NULL;
    tui_dashboard_t *tui = (tui_dashboard_t*)calloc(1, sizeof(tui_dashboard_t));
    if (!tui) return NULL;

    tui->state = state;
    tui->metrics_port = metrics_port;
    tui->running = true;
    tui->start_time = time(NULL);

    if (pthread_create(&tui->thread, NULL, tui_render_loop, tui) != 0) {
        free(tui);
        return NULL;
    }
    return tui;
}

void tui_stop(tui_dashboard_t *tui) {
    if (!tui) return;
    tui->running = false;
    pthread_join(tui->thread, NULL);
    free(tui);
}
