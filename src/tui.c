#include "coresentinel/tui.h"
#include <arpa/inet.h>
#include <curses.h>
#include <locale.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

/* Color Pair Definitions */
#define PAIR_DEFAULT         1
#define PAIR_HEADER          2
#define PAIR_ACTIVE_TAB      3
#define PAIR_INACTIVE_TAB    4
#define PAIR_SELECTED_ROW    5
#define PAIR_STATUS_OK       6
#define PAIR_STATUS_WARN     7
#define PAIR_STATUS_ALERT    8
#define PAIR_STATUS_CRIT     9
#define PAIR_METRIC_ACCENT   10
#define PAIR_DIM_GRAY        11
#define PAIR_MODAL_BOX       12
#define PAIR_MODAL_TITLE     13

#define NUM_TABS 5
enum {
    TAB_OVERVIEW = 0,
    TAB_EXECS    = 1,
    TAB_SOCKETS  = 2,
    TAB_ALERTS   = 3,
    TAB_FILES    = 4,
};

static const char *TAB_NAMES[NUM_TABS] = {
    "1: Overview",
    "2: Executions",
    "3: Sockets",
    "4: Security Alerts",
    "5: File Integrity"
};

typedef struct {
    uint64_t total_events;
    uint64_t total_execs;
    uint64_t total_connects;
    uint64_t total_file_opens;
    uint64_t total_priv_esc;
    uint64_t total_alerts;
    uint64_t alerts_by_sev[5];

    int num_execs;
    struct sentinel_event execs[MAX_RECENT_EXECS];

    int num_conns;
    struct sentinel_event conns[MAX_RECENT_CONNS];

    int num_alerts;
    struct sentinel_event alerts[MAX_RECENT_ALERTS];

    int num_files;
    struct sentinel_event files[MAX_RECENT_FILES];
} tui_snapshot_t;

struct tui_dashboard {
    anomaly_state_t *state;
    int metrics_port;
    pthread_t thread;
    volatile bool running;
    time_t start_time;

    int active_tab;
    int selected_row[NUM_TABS];
    int scroll_offset[NUM_TABS];
    bool is_paused;
    bool show_modal;
    struct sentinel_event modal_event;

    tui_snapshot_t cached_snapshot;
};

static void init_tui_colors(void) {
    start_color();
    use_default_colors();

    init_pair(PAIR_DEFAULT,       COLOR_WHITE,   -1);
    init_pair(PAIR_HEADER,        COLOR_CYAN,    -1);
    init_pair(PAIR_ACTIVE_TAB,    COLOR_WHITE,   COLOR_BLUE);
    init_pair(PAIR_INACTIVE_TAB,  COLOR_CYAN,    -1);
    init_pair(PAIR_SELECTED_ROW,  COLOR_BLACK,   COLOR_CYAN);
    init_pair(PAIR_STATUS_OK,     COLOR_GREEN,   -1);
    init_pair(PAIR_STATUS_WARN,   COLOR_YELLOW,  -1);
    init_pair(PAIR_STATUS_ALERT,  COLOR_RED,     -1);
    init_pair(PAIR_STATUS_CRIT,   COLOR_WHITE,   COLOR_RED);
    init_pair(PAIR_METRIC_ACCENT, COLOR_MAGENTA, -1);
    init_pair(PAIR_DIM_GRAY,      COLOR_WHITE,   -1);
    init_pair(PAIR_MODAL_BOX,     COLOR_CYAN,    COLOR_BLACK);
    init_pair(PAIR_MODAL_TITLE,   COLOR_BLACK,   COLOR_CYAN);
}

static void copy_snapshot(anomaly_state_t *state, tui_snapshot_t *snap) {
    pthread_mutex_lock(&state->lock);

    snap->total_events = state->total_events;
    snap->total_execs = state->total_execs;
    snap->total_connects = state->total_connects;
    snap->total_file_opens = state->total_file_opens;
    snap->total_priv_esc = state->total_priv_esc;
    snap->total_alerts = state->total_alerts;
    for (int i = 0; i < 5; i++) {
        snap->alerts_by_sev[i] = state->alerts_by_sev[i];
    }

    snap->num_execs = state->exec_count;
    for (int i = 0; i < snap->num_execs; i++) {
        int idx = (state->exec_head - 1 - i + MAX_RECENT_EXECS) % MAX_RECENT_EXECS;
        snap->execs[i] = state->recent_execs[idx];
    }

    snap->num_conns = state->conn_count;
    for (int i = 0; i < snap->num_conns; i++) {
        int idx = (state->conn_head - 1 - i + MAX_RECENT_CONNS) % MAX_RECENT_CONNS;
        snap->conns[i] = state->recent_conns[idx];
    }

    snap->num_alerts = state->alert_count;
    for (int i = 0; i < snap->num_alerts; i++) {
        int idx = (state->alert_head - 1 - i + MAX_RECENT_ALERTS) % MAX_RECENT_ALERTS;
        snap->alerts[i] = state->recent_alerts[idx];
    }

    snap->num_files = state->file_count;
    for (int i = 0; i < snap->num_files; i++) {
        int idx = (state->file_head - 1 - i + MAX_RECENT_FILES) % MAX_RECENT_FILES;
        snap->files[i] = state->recent_files[idx];
    }

    pthread_mutex_unlock(&state->lock);
}

static const char* format_ip_addr(uint32_t ip, char *buf, size_t buflen) {
    struct in_addr in;
    in.s_addr = ip;
    inet_ntop(AF_INET, &in, buf, buflen);
    return buf;
}

static void draw_header(tui_dashboard_t *tui, int max_x, const tui_snapshot_t *snap) {
    time_t now = time(NULL);
    long uptime = (long)(now - tui->start_time);
    int up_h = (int)(uptime / 3600);
    int up_m = (int)((uptime % 3600) / 60);
    int up_s = (int)(uptime % 60);

    // Title line
    attron(COLOR_PAIR(PAIR_HEADER) | A_BOLD);
    mvprintw(0, 1, "CoreSentinel");
    attroff(COLOR_PAIR(PAIR_HEADER) | A_BOLD);
    attron(COLOR_PAIR(PAIR_DEFAULT));
    printw(" | eBPF Linux Kernel Security & Observability (CO-RE)");

    // Status badges on row 0 right-aligned
    int right_pos = max_x - 36;
    if (right_pos > 45) {
        move(0, right_pos);
        printw("[Kernel: ");
        attron(COLOR_PAIR(PAIR_STATUS_OK) | A_BOLD);
        printw("● LIVE");
        attroff(COLOR_PAIR(PAIR_STATUS_OK) | A_BOLD);
        attron(COLOR_PAIR(PAIR_DEFAULT));
        printw("] [State: ");
        if (tui->is_paused) {
            attron(COLOR_PAIR(PAIR_STATUS_WARN) | A_BOLD);
            printw("PAUSED");
            attroff(COLOR_PAIR(PAIR_STATUS_WARN) | A_BOLD);
        } else {
            attron(COLOR_PAIR(PAIR_STATUS_OK) | A_BOLD);
            printw("ACTIVE");
            attroff(COLOR_PAIR(PAIR_STATUS_OK) | A_BOLD);
        }
        attron(COLOR_PAIR(PAIR_DEFAULT));
        printw("]");
    }

    // Telemetry strip on row 1
    move(1, 1);
    attron(COLOR_PAIR(PAIR_DIM_GRAY));
    printw("Uptime: ");
    attroff(COLOR_PAIR(PAIR_DIM_GRAY));
    attron(COLOR_PAIR(PAIR_METRIC_ACCENT) | A_BOLD);
    printw("%02d:%02d:%02d", up_h, up_m, up_s);
    attroff(COLOR_PAIR(PAIR_METRIC_ACCENT) | A_BOLD);

    attron(COLOR_PAIR(PAIR_DIM_GRAY));
    printw(" | Metrics: ");
    attroff(COLOR_PAIR(PAIR_DIM_GRAY));
    attron(COLOR_PAIR(PAIR_HEADER));
    printw("http://127.0.0.1:%-5d", tui->metrics_port);
    attroff(COLOR_PAIR(PAIR_HEADER));

    attron(COLOR_PAIR(PAIR_DIM_GRAY));
    printw(" | Total Events: ");
    attroff(COLOR_PAIR(PAIR_DIM_GRAY));
    attron(COLOR_PAIR(PAIR_DEFAULT) | A_BOLD);
    printw("%-8llu", (unsigned long long)snap->total_events);
    attroff(COLOR_PAIR(PAIR_DEFAULT) | A_BOLD);

    attron(COLOR_PAIR(PAIR_DIM_GRAY));
    printw(" | Alerts: ");
    attroff(COLOR_PAIR(PAIR_DIM_GRAY));
    if (snap->total_alerts > 0) {
        attron(COLOR_PAIR(PAIR_STATUS_ALERT) | A_BOLD);
        printw("%-5llu", (unsigned long long)snap->total_alerts);
        attroff(COLOR_PAIR(PAIR_STATUS_ALERT) | A_BOLD);
    } else {
        attron(COLOR_PAIR(PAIR_STATUS_OK) | A_BOLD);
        printw("0    ");
        attroff(COLOR_PAIR(PAIR_STATUS_OK) | A_BOLD);
    }

    // Horizontal separator
    mvhline(2, 0, ACS_HLINE, max_x);
}

static void draw_tabs(tui_dashboard_t *tui, int max_x) {
    int col = 2;
    for (int i = 0; i < NUM_TABS; i++) {
        char buf[32];
        snprintf(buf, sizeof(buf), "  %s  ", TAB_NAMES[i]);
        int len = strlen(buf);

        if (col + len >= max_x - 1) break;

        if (i == tui->active_tab) {
            attron(COLOR_PAIR(PAIR_ACTIVE_TAB) | A_BOLD);
            mvprintw(3, col, "%s", buf);
            attroff(COLOR_PAIR(PAIR_ACTIVE_TAB) | A_BOLD);
        } else {
            attron(COLOR_PAIR(PAIR_INACTIVE_TAB));
            mvprintw(3, col, "%s", buf);
            attroff(COLOR_PAIR(PAIR_INACTIVE_TAB));
        }
        col += len + 1;
    }

    mvhline(4, 0, ACS_HLINE, max_x);
}

static void draw_overview_tab(int start_y, int max_y, int max_x, const tui_snapshot_t *snap) {
    int available_rows = max_y - start_y - 2;
    if (available_rows < 6) return;

    // Left Column: System Architecture & Engine Health
    int left_w = (max_x > 90) ? 46 : (max_x / 2 - 1);
    if (left_w < 35) left_w = 35;

    attron(COLOR_PAIR(PAIR_HEADER) | A_BOLD);
    mvprintw(start_y, 2, "[ SYSTEM STATUS & KERNEL PROBES ]");
    attroff(COLOR_PAIR(PAIR_HEADER) | A_BOLD);

    mvprintw(start_y + 1, 3, "eBPF Probes Status : ");
    attron(COLOR_PAIR(PAIR_STATUS_OK) | A_BOLD);
    printw("ATTACHED (CO-RE)");
    attroff(COLOR_PAIR(PAIR_STATUS_OK) | A_BOLD);

    mvprintw(start_y + 2, 3, "Tracepoint execve  : ");
    attron(COLOR_PAIR(PAIR_STATUS_OK));
    printw("sys_enter_execve (PID/UID)");
    attroff(COLOR_PAIR(PAIR_STATUS_OK));

    mvprintw(start_y + 3, 3, "KProbe tcp_connect : ");
    attron(COLOR_PAIR(PAIR_STATUS_OK));
    printw("tcp_v4_connect (Egress)");
    attroff(COLOR_PAIR(PAIR_STATUS_OK));

    mvprintw(start_y + 4, 3, "Tracepoint openat  : ");
    attron(COLOR_PAIR(PAIR_STATUS_OK));
    printw("sys_enter_openat (Files)");
    attroff(COLOR_PAIR(PAIR_STATUS_OK));

    mvprintw(start_y + 5, 3, "KProbe commit_creds: ");
    attron(COLOR_PAIR(PAIR_STATUS_OK));
    printw("commit_creds (PrivEsc)");
    attroff(COLOR_PAIR(PAIR_STATUS_OK));

    mvprintw(start_y + 6, 3, "Ring Buffer Mode   : ");
    attron(COLOR_PAIR(PAIR_METRIC_ACCENT));
    printw("Lockless RingBuffer 256KB");
    attroff(COLOR_PAIR(PAIR_METRIC_ACCENT));

    // Right Column: Telemetry & Threat Metrics
    int right_col = left_w + 5;
    if (right_col + 35 < max_x) {
        attron(COLOR_PAIR(PAIR_HEADER) | A_BOLD);
        mvprintw(start_y, right_col, "[ EVENT METRICS BREAKDOWN ]");
        attroff(COLOR_PAIR(PAIR_HEADER) | A_BOLD);

        mvprintw(start_y + 1, right_col + 1, "Executions (execve)   : %-8llu", (unsigned long long)snap->total_execs);
        mvprintw(start_y + 2, right_col + 1, "TCP Sockets (connect) : %-8llu", (unsigned long long)snap->total_connects);
        mvprintw(start_y + 3, right_col + 1, "File Opens (openat)   : %-8llu", (unsigned long long)snap->total_file_opens);
        mvprintw(start_y + 4, right_col + 1, "Privilege Escalations : %-8llu", (unsigned long long)snap->total_priv_esc);

        mvprintw(start_y + 6, right_col, "[ SEVERITY DISTRIBUTION ]");
        mvprintw(start_y + 7, right_col + 1, "CRITICAL : %-4llu ", (unsigned long long)snap->alerts_by_sev[SENTINEL_SEV_CRITICAL]);
        attron(COLOR_PAIR(PAIR_STATUS_CRIT));
        for (uint64_t i = 0; i < (snap->alerts_by_sev[SENTINEL_SEV_CRITICAL] > 15 ? 15 : snap->alerts_by_sev[SENTINEL_SEV_CRITICAL]); i++) addch('#');
        attroff(COLOR_PAIR(PAIR_STATUS_CRIT));

        mvprintw(start_y + 8, right_col + 1, "HIGH     : %-4llu ", (unsigned long long)snap->alerts_by_sev[SENTINEL_SEV_HIGH]);
        attron(COLOR_PAIR(PAIR_STATUS_ALERT));
        for (uint64_t i = 0; i < (snap->alerts_by_sev[SENTINEL_SEV_HIGH] > 15 ? 15 : snap->alerts_by_sev[SENTINEL_SEV_HIGH]); i++) addch('#');
        attroff(COLOR_PAIR(PAIR_STATUS_ALERT));

        mvprintw(start_y + 9, right_col + 1, "MEDIUM   : %-4llu ", (unsigned long long)snap->alerts_by_sev[SENTINEL_SEV_MEDIUM]);
        attron(COLOR_PAIR(PAIR_STATUS_WARN));
        for (uint64_t i = 0; i < (snap->alerts_by_sev[SENTINEL_SEV_MEDIUM] > 15 ? 15 : snap->alerts_by_sev[SENTINEL_SEV_MEDIUM]); i++) addch('#');
        attroff(COLOR_PAIR(PAIR_STATUS_WARN));
    }

    // Lower Section: Recent Real-Time Activity Feed
    int feed_y = start_y + 11;
    if (feed_y < max_y - 2) {
        mvhline(feed_y - 1, 2, ACS_HLINE, max_x - 4);
        attron(COLOR_PAIR(PAIR_HEADER) | A_BOLD);
        mvprintw(feed_y, 2, "[ RECENT SECURITY ALERTS TICKER ]");
        attroff(COLOR_PAIR(PAIR_HEADER) | A_BOLD);

        if (snap->num_alerts == 0) {
            attron(COLOR_PAIR(PAIR_STATUS_OK));
            mvprintw(feed_y + 2, 4, "✔ No security anomalies detected. System operating normally.");
            attroff(COLOR_PAIR(PAIR_STATUS_OK));
        } else {
            int max_feed_items = max_y - feed_y - 3;
            if (max_feed_items > 5) max_feed_items = 5;
            for (int i = 0; i < max_feed_items && i < snap->num_alerts; i++) {
                const struct sentinel_event *e = &snap->alerts[i];
                int line_y = feed_y + 2 + i;
                move(line_y, 4);

                if (e->severity == SENTINEL_SEV_CRITICAL) {
                    attron(COLOR_PAIR(PAIR_STATUS_CRIT) | A_BOLD);
                    printw(" CRITICAL ");
                    attroff(COLOR_PAIR(PAIR_STATUS_CRIT) | A_BOLD);
                } else if (e->severity == SENTINEL_SEV_HIGH) {
                    attron(COLOR_PAIR(PAIR_STATUS_ALERT) | A_BOLD);
                    printw(" HIGH     ");
                    attroff(COLOR_PAIR(PAIR_STATUS_ALERT) | A_BOLD);
                } else {
                    attron(COLOR_PAIR(PAIR_STATUS_WARN) | A_BOLD);
                    printw(" MEDIUM   ");
                    attroff(COLOR_PAIR(PAIR_STATUS_WARN) | A_BOLD);
                }

                printw(" PID:%-6u COMM:%-12s ", e->pid, e->comm);
                char msg[80];
                snprintf(msg, sizeof(msg), "%s", e->alert_msg);
                printw("%s", msg);
            }
        }
    }
}

static void draw_executions_tab(tui_dashboard_t *tui, int start_y, int max_y, int max_x, const tui_snapshot_t *snap) {
    attron(COLOR_PAIR(PAIR_HEADER) | A_BOLD);
    mvprintw(start_y, 2, "%-7s %-6s %-14s %-14s %-38s %-12s",
             "PID", "UID", "COMM", "PARENT", "BINARY PATH", "STATUS");
    attroff(COLOR_PAIR(PAIR_HEADER) | A_BOLD);
    mvhline(start_y + 1, 2, ACS_HLINE, max_x - 4);

    int rows = max_y - start_y - 3;
    if (rows <= 0) return;

    if (snap->num_execs == 0) {
        attron(COLOR_PAIR(PAIR_DIM_GRAY));
        mvprintw(start_y + 3, 4, "(Waiting for process execution events...)");
        attroff(COLOR_PAIR(PAIR_DIM_GRAY));
        return;
    }

    int current_sel = tui->selected_row[TAB_EXECS];
    if (current_sel >= snap->num_execs) current_sel = snap->num_execs - 1;
    if (current_sel < 0) current_sel = 0;
    tui->selected_row[TAB_EXECS] = current_sel;

    int offset = tui->scroll_offset[TAB_EXECS];
    if (current_sel < offset) offset = current_sel;
    if (current_sel >= offset + rows) offset = current_sel - rows + 1;
    tui->scroll_offset[TAB_EXECS] = offset;

    for (int i = 0; i < rows && (offset + i) < snap->num_execs; i++) {
        int idx = offset + i;
        const struct sentinel_event *e = &snap->execs[idx];
        int y = start_y + 2 + i;

        bool is_selected = (idx == current_sel);
        if (is_selected) {
            attron(COLOR_PAIR(PAIR_SELECTED_ROW) | A_BOLD);
            mvhline(y, 1, ' ', max_x - 2);
        }

        char path_buf[40];
        snprintf(path_buf, sizeof(path_buf), "%s", e->filename);

        mvprintw(y, 2, "%-7u %-6u %-14s %-14s %-38s ",
                 e->pid,
                 e->uid,
                 e->comm,
                 e->pcomm[0] ? e->pcomm : "-",
                 path_buf);

        if (!is_selected) {
            if (e->is_suspicious_path) {
                attron(COLOR_PAIR(PAIR_STATUS_ALERT) | A_BOLD);
                printw("[SUSPICIOUS]");
                attroff(COLOR_PAIR(PAIR_STATUS_ALERT) | A_BOLD);
            } else {
                attron(COLOR_PAIR(PAIR_STATUS_OK));
                printw("[VERIFIED]  ");
                attroff(COLOR_PAIR(PAIR_STATUS_OK));
            }
        } else {
            printw("%s", e->is_suspicious_path ? "[SUSPICIOUS]" : "[VERIFIED]  ");
            attroff(COLOR_PAIR(PAIR_SELECTED_ROW) | A_BOLD);
        }
    }
}

static void draw_sockets_tab(tui_dashboard_t *tui, int start_y, int max_y, int max_x, const tui_snapshot_t *snap) {
    attron(COLOR_PAIR(PAIR_HEADER) | A_BOLD);
    mvprintw(start_y, 2, "%-7s %-6s %-14s %-28s %-8s %-12s",
             "PID", "UID", "COMM", "REMOTE ENDPOINT", "PROTO", "STATUS");
    attroff(COLOR_PAIR(PAIR_HEADER) | A_BOLD);
    mvhline(start_y + 1, 2, ACS_HLINE, max_x - 4);

    int rows = max_y - start_y - 3;
    if (rows <= 0) return;

    if (snap->num_conns == 0) {
        attron(COLOR_PAIR(PAIR_DIM_GRAY));
        mvprintw(start_y + 3, 4, "(Waiting for socket connection events...)");
        attroff(COLOR_PAIR(PAIR_DIM_GRAY));
        return;
    }

    int current_sel = tui->selected_row[TAB_SOCKETS];
    if (current_sel >= snap->num_conns) current_sel = snap->num_conns - 1;
    if (current_sel < 0) current_sel = 0;
    tui->selected_row[TAB_SOCKETS] = current_sel;

    int offset = tui->scroll_offset[TAB_SOCKETS];
    if (current_sel < offset) offset = current_sel;
    if (current_sel >= offset + rows) offset = current_sel - rows + 1;
    tui->scroll_offset[TAB_SOCKETS] = offset;

    for (int i = 0; i < rows && (offset + i) < snap->num_conns; i++) {
        int idx = offset + i;
        const struct sentinel_event *e = &snap->conns[idx];
        int y = start_y + 2 + i;

        bool is_selected = (idx == current_sel);
        if (is_selected) {
            attron(COLOR_PAIR(PAIR_SELECTED_ROW) | A_BOLD);
            mvhline(y, 1, ' ', max_x - 2);
        }

        char ip_str[32];
        char ep_str[40];
        format_ip_addr(e->daddr, ip_str, sizeof(ip_str));
        snprintf(ep_str, sizeof(ep_str), "%s:%u", ip_str, e->dport);

        mvprintw(y, 2, "%-7u %-6u %-14s %-28s %-8s ",
                 e->pid,
                 e->uid,
                 e->comm,
                 ep_str,
                 "TCP");

        if (!is_selected) {
            if (e->severity >= SENTINEL_SEV_HIGH) {
                attron(COLOR_PAIR(PAIR_STATUS_ALERT) | A_BOLD);
                printw("[SUSPICIOUS]");
                attroff(COLOR_PAIR(PAIR_STATUS_ALERT) | A_BOLD);
            } else {
                attron(COLOR_PAIR(PAIR_STATUS_OK));
                printw("[NORMAL]    ");
                attroff(COLOR_PAIR(PAIR_STATUS_OK));
            }
        } else {
            printw("%s", (e->severity >= SENTINEL_SEV_HIGH) ? "[SUSPICIOUS]" : "[NORMAL]    ");
            attroff(COLOR_PAIR(PAIR_SELECTED_ROW) | A_BOLD);
        }
    }
}

static void draw_alerts_tab(tui_dashboard_t *tui, int start_y, int max_y, int max_x, const tui_snapshot_t *snap) {
    attron(COLOR_PAIR(PAIR_HEADER) | A_BOLD);
    mvprintw(start_y, 2, "%-12s %-7s %-14s %-48s",
             "SEVERITY", "PID", "COMM", "ALERT DETAILS");
    attroff(COLOR_PAIR(PAIR_HEADER) | A_BOLD);
    mvhline(start_y + 1, 2, ACS_HLINE, max_x - 4);

    int rows = max_y - start_y - 3;
    if (rows <= 0) return;

    if (snap->num_alerts == 0) {
        attron(COLOR_PAIR(PAIR_STATUS_OK) | A_BOLD);
        mvprintw(start_y + 3, 4, "✔ No security anomalies detected. System operating within baseline.");
        attroff(COLOR_PAIR(PAIR_STATUS_OK) | A_BOLD);
        return;
    }

    int current_sel = tui->selected_row[TAB_ALERTS];
    if (current_sel >= snap->num_alerts) current_sel = snap->num_alerts - 1;
    if (current_sel < 0) current_sel = 0;
    tui->selected_row[TAB_ALERTS] = current_sel;

    int offset = tui->scroll_offset[TAB_ALERTS];
    if (current_sel < offset) offset = current_sel;
    if (current_sel >= offset + rows) offset = current_sel - rows + 1;
    tui->scroll_offset[TAB_ALERTS] = offset;

    for (int i = 0; i < rows && (offset + i) < snap->num_alerts; i++) {
        int idx = offset + i;
        const struct sentinel_event *e = &snap->alerts[idx];
        int y = start_y + 2 + i;

        bool is_selected = (idx == current_sel);
        if (is_selected) {
            attron(COLOR_PAIR(PAIR_SELECTED_ROW) | A_BOLD);
            mvhline(y, 1, ' ', max_x - 2);
        }

        const char *sev_str;
        int sev_pair;
        if (e->severity == SENTINEL_SEV_CRITICAL) {
            sev_str = "CRITICAL";
            sev_pair = PAIR_STATUS_CRIT;
        } else if (e->severity == SENTINEL_SEV_HIGH) {
            sev_str = "HIGH";
            sev_pair = PAIR_STATUS_ALERT;
        } else {
            sev_str = "MEDIUM";
            sev_pair = PAIR_STATUS_WARN;
        }

        move(y, 2);
        if (!is_selected) {
            attron(COLOR_PAIR(sev_pair) | A_BOLD);
            printw("[%-8s]", sev_str);
            attroff(COLOR_PAIR(sev_pair) | A_BOLD);
        } else {
            printw("[%-8s]", sev_str);
        }

        char alert_buf[60];
        snprintf(alert_buf, sizeof(alert_buf), "%s", e->alert_msg);

        printw(" %-7u %-14s %s",
               e->pid,
               e->comm,
               alert_buf);

        if (is_selected) {
            attroff(COLOR_PAIR(PAIR_SELECTED_ROW) | A_BOLD);
        }
    }
}

static void draw_files_tab(tui_dashboard_t *tui, int start_y, int max_y, int max_x, const tui_snapshot_t *snap) {
    attron(COLOR_PAIR(PAIR_HEADER) | A_BOLD);
    mvprintw(start_y, 2, "%-7s %-6s %-14s %-8s %-14s %-36s",
             "PID", "UID", "COMM", "ACCESS", "INTEGRITY", "FILE PATH");
    attroff(COLOR_PAIR(PAIR_HEADER) | A_BOLD);
    mvhline(start_y + 1, 2, ACS_HLINE, max_x - 4);

    int rows = max_y - start_y - 3;
    if (rows <= 0) return;

    if (snap->num_files == 0) {
        attron(COLOR_PAIR(PAIR_DIM_GRAY));
        mvprintw(start_y + 3, 4, "(Waiting for file open events...)");
        attroff(COLOR_PAIR(PAIR_DIM_GRAY));
        return;
    }

    int current_sel = tui->selected_row[TAB_FILES];
    if (current_sel >= snap->num_files) current_sel = snap->num_files - 1;
    if (current_sel < 0) current_sel = 0;
    tui->selected_row[TAB_FILES] = current_sel;

    int offset = tui->scroll_offset[TAB_FILES];
    if (current_sel < offset) offset = current_sel;
    if (current_sel >= offset + rows) offset = current_sel - rows + 1;
    tui->scroll_offset[TAB_FILES] = offset;

    for (int i = 0; i < rows && (offset + i) < snap->num_files; i++) {
        int idx = offset + i;
        const struct sentinel_event *e = &snap->files[idx];
        int y = start_y + 2 + i;

        bool is_selected = (idx == current_sel);
        if (is_selected) {
            attron(COLOR_PAIR(PAIR_SELECTED_ROW) | A_BOLD);
            mvhline(y, 1, ' ', max_x - 2);
        }

        char path_buf[48];
        snprintf(path_buf, sizeof(path_buf), "%s", e->file_path);

        mvprintw(y, 2, "%-7u %-6u %-14s %-8s ",
                 e->pid,
                 e->uid,
                 e->comm,
                 e->is_write_access ? "WRITE" : "READ");

        if (!is_selected) {
            if (e->is_sensitive_file) {
                attron(COLOR_PAIR(PAIR_STATUS_ALERT) | A_BOLD);
                printw("[PROTECTED]  ");
                attroff(COLOR_PAIR(PAIR_STATUS_ALERT) | A_BOLD);
            } else {
                attron(COLOR_PAIR(PAIR_STATUS_OK));
                printw("[STANDARD]   ");
                attroff(COLOR_PAIR(PAIR_STATUS_OK));
            }
        } else {
            printw("%s", e->is_sensitive_file ? "[PROTECTED]  " : "[STANDARD]   ");
        }

        printw("%-36s", path_buf);

        if (is_selected) {
            attroff(COLOR_PAIR(PAIR_SELECTED_ROW) | A_BOLD);
        }
    }
}

static void draw_modal_dialog(tui_dashboard_t *tui, int max_y, int max_x) {
    if (!tui->show_modal) return;

    int mw = 74;
    int mh = 18;
    if (mw > max_x - 4) mw = max_x - 4;
    if (mh > max_y - 2) mh = max_y - 2;

    int my = (max_y - mh) / 2;
    int mx = (max_x - mw) / 2;

    // Draw background and border
    attron(COLOR_PAIR(PAIR_MODAL_BOX));
    for (int y = my; y < my + mh; y++) {
        mvhline(y, mx, ' ', mw);
    }
    // Outer box
    mvhline(my, mx, ACS_HLINE, mw);
    mvhline(my + mh - 1, mx, ACS_HLINE, mw);
    mvvline(my, mx, ACS_VLINE, mh);
    mvvline(my, mx + mw - 1, ACS_VLINE, mh);
    mvaddch(my, mx, ACS_ULCORNER);
    mvaddch(my, mx + mw - 1, ACS_URCORNER);
    mvaddch(my + mh - 1, mx, ACS_LLCORNER);
    mvaddch(my + mh - 1, mx + mw - 1, ACS_LRCORNER);
    attroff(COLOR_PAIR(PAIR_MODAL_BOX));

    // Title header
    attron(COLOR_PAIR(PAIR_MODAL_TITLE) | A_BOLD);
    mvprintw(my, mx + 3, " [ EVENT METADATA INSPECTION ] ");
    attroff(COLOR_PAIR(PAIR_MODAL_TITLE) | A_BOLD);

    const struct sentinel_event *e = &tui->modal_event;
    int cur_y = my + 2;

    attron(COLOR_PAIR(PAIR_MODAL_BOX));
    mvprintw(cur_y++, mx + 3, "Event Type  : %s", sentinel_event_type_str(e->event_type));
    mvprintw(cur_y++, mx + 3, "Severity    : %s (level %u)", sentinel_severity_str(e->severity), e->severity);
    mvprintw(cur_y++, mx + 3, "Process     : PID %u | PPID %u | UID %u | GID %u", e->pid, e->ppid, e->uid, e->gid);
    mvprintw(cur_y++, mx + 3, "Command     : %s (Parent: %s)", e->comm, e->pcomm[0] ? e->pcomm : "N/A");

    if (e->event_type == EVENT_EXEC) {
        mvprintw(cur_y++, mx + 3, "Binary Path : %s", e->filename);
        mvprintw(cur_y++, mx + 3, "Path Status : %s", e->is_suspicious_path ? "FLAGGED SUSPICIOUS (/tmp,/dev/shm)" : "VERIFIED STANDARD PATH");
    } else if (e->event_type == EVENT_CONNECT) {
        char ip_str[32];
        format_ip_addr(e->daddr, ip_str, sizeof(ip_str));
        mvprintw(cur_y++, mx + 3, "Destination : %s:%u (Proto: TCP)", ip_str, e->dport);
        mvprintw(cur_y++, mx + 3, "Threat Flag : %s", (e->severity >= SENTINEL_SEV_HIGH) ? "FLAGGED KNOWN THREAT/C2 PORT" : "STANDARD EGRESS");
    } else if (e->event_type == EVENT_FILE_OPEN) {
        mvprintw(cur_y++, mx + 3, "File Path   : %s", e->file_path);
        mvprintw(cur_y++, mx + 3, "Operation   : %s | Flag: %s",
                 e->is_write_access ? "WRITE/MODIFY" : "READ ONLY",
                 e->is_sensitive_file ? "CRITICAL SENSITIVE ASSET (/etc/shadow, pam, sudoers)" : "STANDARD FILE");
    } else if (e->event_type == EVENT_PRIV_ESC) {
        mvprintw(cur_y++, mx + 3, "Privilege   : Transition UID %u -> %u (ROOT ELEVATION)", e->old_uid, e->uid);
    }

    if (e->alert_msg[0]) {
        cur_y++;
        mvprintw(cur_y++, mx + 3, "Alert Detail: %s", e->alert_msg);
    }

    // Modal Footer
    attron(COLOR_PAIR(PAIR_DIM_GRAY));
    mvprintw(my + mh - 2, mx + 3, "Press [Enter], [Esc], or [q] to close this inspection view");
    attroff(COLOR_PAIR(PAIR_DIM_GRAY));
    attroff(COLOR_PAIR(PAIR_MODAL_BOX));
}

static void draw_footer(tui_dashboard_t *tui, int max_y, int max_x) {
    mvhline(max_y - 2, 0, ACS_HLINE, max_x);

    move(max_y - 1, 1);
    attron(COLOR_PAIR(PAIR_HEADER) | A_BOLD);
    printw("Keys: ");
    attroff(COLOR_PAIR(PAIR_HEADER) | A_BOLD);

    attron(COLOR_PAIR(PAIR_DEFAULT));
    printw("[1-5/Tab]");
    attron(COLOR_PAIR(PAIR_DIM_GRAY));
    printw(" Switch Tab  ");
    attroff(COLOR_PAIR(PAIR_DIM_GRAY));

    attron(COLOR_PAIR(PAIR_DEFAULT));
    printw("[↑/↓/j/k]");
    attron(COLOR_PAIR(PAIR_DIM_GRAY));
    printw(" Select  ");
    attroff(COLOR_PAIR(PAIR_DIM_GRAY));

    attron(COLOR_PAIR(PAIR_DEFAULT));
    printw("[Enter]");
    attron(COLOR_PAIR(PAIR_DIM_GRAY));
    printw(" Inspect  ");
    attroff(COLOR_PAIR(PAIR_DIM_GRAY));

    attron(COLOR_PAIR(PAIR_DEFAULT));
    printw("[Space]");
    attron(COLOR_PAIR(PAIR_DIM_GRAY));
    printw(" Pause/Resume  ");
    attroff(COLOR_PAIR(PAIR_DIM_GRAY));

    attron(COLOR_PAIR(PAIR_DEFAULT));
    printw("[q]");
    attron(COLOR_PAIR(PAIR_DIM_GRAY));
    printw(" Quit");
    attroff(COLOR_PAIR(PAIR_DIM_GRAY));

    if (tui->is_paused) {
        int warn_x = max_x - 30;
        if (warn_x > 50) {
            attron(COLOR_PAIR(PAIR_STATUS_WARN) | A_BOLD);
            mvprintw(max_y - 1, warn_x, "[ LIVE FEED PAUSED ]");
            attroff(COLOR_PAIR(PAIR_STATUS_WARN) | A_BOLD);
        }
    }
}

static void* tui_render_loop(void *arg) {
    tui_dashboard_t *tui = (tui_dashboard_t*)arg;

    setlocale(LC_ALL, "");
    initscr();
    cbreak();
    noecho();
    keypad(stdscr, TRUE);
    curs_set(0);
    wtimeout(stdscr, 100); /* 100ms non-blocking getch */

    init_tui_colors();

    tui_snapshot_t snap;
    memset(&snap, 0, sizeof(snap));

    while (tui->running) {
        if (!tui->is_paused) {
            copy_snapshot(tui->state, &snap);
            tui->cached_snapshot = snap;
        } else {
            snap = tui->cached_snapshot;
        }

        int max_y, max_x;
        getmaxyx(stdscr, max_y, max_x);

        erase();

        if (max_y < 15 || max_x < 55) {
            attron(COLOR_PAIR(PAIR_STATUS_WARN) | A_BOLD);
            mvprintw(max_y / 2, (max_x > 38 ? (max_x - 38) / 2 : 1), "Terminal size too small (min 55x15)");
            attroff(COLOR_PAIR(PAIR_STATUS_WARN) | A_BOLD);
            refresh();
            int ch = getch();
            if (ch == 'q' || ch == 'Q') {
                tui->running = false;
                break;
            }
            continue;
        }

        draw_header(tui, max_x, &snap);
        draw_tabs(tui, max_x);

        int content_y = 5;
        switch (tui->active_tab) {
            case TAB_OVERVIEW:
                draw_overview_tab(content_y, max_y, max_x, &snap);
                break;
            case TAB_EXECS:
                draw_executions_tab(tui, content_y, max_y, max_x, &snap);
                break;
            case TAB_SOCKETS:
                draw_sockets_tab(tui, content_y, max_y, max_x, &snap);
                break;
            case TAB_ALERTS:
                draw_alerts_tab(tui, content_y, max_y, max_x, &snap);
                break;
            case TAB_FILES:
                draw_files_tab(tui, content_y, max_y, max_x, &snap);
                break;
            default:
                break;
        }

        draw_footer(tui, max_y, max_x);

        if (tui->show_modal) {
            draw_modal_dialog(tui, max_y, max_x);
        }

        refresh();

        int ch = getch();
        if (ch == ERR) {
            continue;
        }

        if (ch == KEY_RESIZE) {
            continue;
        }

        if (tui->show_modal) {
            if (ch == '\n' || ch == '\r' || ch == 27 || ch == 'q' || ch == 'Q' || ch == 'x' || ch == 'X') {
                tui->show_modal = false;
            }
            continue;
        }

        switch (ch) {
            case 'q':
            case 'Q':
                tui->running = false;
                break;

            case ' ':
                tui->is_paused = !tui->is_paused;
                break;

            case '\t':
                tui->active_tab = (tui->active_tab + 1) % NUM_TABS;
                break;

            case KEY_BTAB:
                tui->active_tab = (tui->active_tab - 1 + NUM_TABS) % NUM_TABS;
                break;

            case '1':
            case '2':
            case '3':
            case '4':
            case '5':
                tui->active_tab = ch - '1';
                break;

            case KEY_DOWN:
            case 'j':
            case 'J':
                tui->selected_row[tui->active_tab]++;
                break;

            case KEY_UP:
            case 'k':
            case 'K':
                if (tui->selected_row[tui->active_tab] > 0) {
                    tui->selected_row[tui->active_tab]--;
                }
                break;

            case 'g':
                tui->selected_row[tui->active_tab] = 0;
                break;

            case 'G':
                tui->selected_row[tui->active_tab] = 9999;
                break;

            case '\n':
            case '\r': {
                int tab = tui->active_tab;
                int row = tui->selected_row[tab];
                if (tab == TAB_EXECS && snap.num_execs > 0) {
                    if (row >= snap.num_execs) row = snap.num_execs - 1;
                    tui->modal_event = snap.execs[row];
                    tui->show_modal = true;
                } else if (tab == TAB_SOCKETS && snap.num_conns > 0) {
                    if (row >= snap.num_conns) row = snap.num_conns - 1;
                    tui->modal_event = snap.conns[row];
                    tui->show_modal = true;
                } else if (tab == TAB_ALERTS && snap.num_alerts > 0) {
                    if (row >= snap.num_alerts) row = snap.num_alerts - 1;
                    tui->modal_event = snap.alerts[row];
                    tui->show_modal = true;
                } else if (tab == TAB_FILES && snap.num_files > 0) {
                    if (row >= snap.num_files) row = snap.num_files - 1;
                    tui->modal_event = snap.files[row];
                    tui->show_modal = true;
                }
                break;
            }

            default:
                break;
        }
    }

    endwin();
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
    tui->active_tab = TAB_OVERVIEW;

    if (pthread_create(&tui->thread, NULL, tui_render_loop, tui) != 0) {
        free(tui);
        return NULL;
    }
    return tui;
}

void tui_stop(tui_dashboard_t *tui) {
    if (!tui) return;
    if (tui->running) {
        tui->running = false;
        pthread_join(tui->thread, NULL);
    }
    free(tui);
}

bool tui_is_running(tui_dashboard_t *tui) {
    if (!tui) return false;
    return tui->running;
}
