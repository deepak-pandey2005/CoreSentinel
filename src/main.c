#include "coresentinel/config.h"
#include "coresentinel/anomaly.h"
#include "coresentinel/engine.h"
#include "coresentinel/metrics.h"
#include "coresentinel/tui.h"
#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static volatile sig_atomic_t g_stop = 0;

static void sig_handler(int sig) {
    (void)sig;
    g_stop = 1;
}

static void print_usage(const char *prog) {
    printf("CoreSentinel: eBPF Linux Kernel Security & Observability Engine\n\n");
    printf("Usage: %s [OPTIONS]\n\n", prog);
    printf("Options:\n");
    printf("  -p, --port <port>     Prometheus metrics HTTP port (default: 9102)\n");
    printf("  -l, --log <file>      Log file path for recorded security events (default: coresentinel.log)\n");
    printf("      --no-tui          Run in headless daemon mode without ANSI terminal UI\n");
    printf("      --no-metrics      Disable embedded Prometheus metrics exporter\n");
    printf("  -v, --verbose         Enable verbose diagnostic logs\n");
    printf("  -h, --help            Show this help manual\n\n");
    printf("Example:\n");
    printf("  sudo %s --port 9102 --log /var/log/coresentinel.log\n", prog);
}

int main(int argc, char **argv) {
    coresentinel_config_t cfg;
    coresentinel_config_default(&cfg);

    static struct option long_options[] = {
        {"port",       required_argument, 0, 'p'},
        {"log",        required_argument, 0, 'l'},
        {"no-tui",     no_argument,       0, 1001},
        {"no-metrics", no_argument,       0, 1002},
        {"verbose",    no_argument,       0, 'v'},
        {"help",       no_argument,       0, 'h'},
        {0, 0, 0, 0}
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "p:l:vh", long_options, NULL)) != -1) {
        switch (opt) {
            case 'p':
                cfg.metrics_port = atoi(optarg);
                break;
            case 'l':
                strncpy(cfg.log_file, optarg, sizeof(cfg.log_file) - 1);
                break;
            case 1001:
                cfg.enable_tui = false;
                break;
            case 1002:
                cfg.enable_metrics = false;
                break;
            case 'v':
                cfg.verbose = true;
                break;
            case 'h':
                print_usage(argv[0]);
                return 0;
            default:
                print_usage(argv[0]);
                return 1;
        }
    }

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = sig_handler;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    anomaly_state_t *anomaly_state = anomaly_state_init();
    if (!anomaly_state) {
        fprintf(stderr, "Fatal: failed to initialize anomaly state\n");
        return 1;
    }

    metrics_server_t *metrics_srv = NULL;
    if (cfg.enable_metrics) {
        metrics_srv = metrics_server_start(cfg.metrics_port, anomaly_state);
        if (!metrics_srv) {
            fprintf(stderr, "Warning: failed to start Prometheus metrics server on port %d\n", cfg.metrics_port);
        }
    }

    tui_dashboard_t *tui = NULL;
    if (cfg.enable_tui) {
        tui = tui_start(anomaly_state, cfg.metrics_port);
    } else {
        printf("[CoreSentinel] Starting eBPF engine in headless mode...\n");
        printf("[CoreSentinel] Logging security events to %s\n", cfg.log_file);
        if (cfg.enable_metrics && metrics_srv) {
            printf("[CoreSentinel] Prometheus metrics active at http://127.0.0.1:%d/metrics\n", cfg.metrics_port);
        }
    }

    coresentinel_engine_t *engine = coresentinel_engine_create(&cfg, anomaly_state);
    if (!engine) {
        fprintf(stderr, "Fatal: failed to initialize eBPF engine. Ensure program runs with root/CAP_BPF privileges.\n");
        if (tui) tui_stop(tui);
        if (metrics_srv) metrics_server_stop(metrics_srv);
        anomaly_state_free(anomaly_state);
        return 1;
    }

    if (coresentinel_engine_start(engine) != 0) {
        fprintf(stderr, "Fatal: failed to start and attach eBPF probes.\n");
        coresentinel_engine_destroy(engine);
        if (tui) tui_stop(tui);
        if (metrics_srv) metrics_server_stop(metrics_srv);
        anomaly_state_free(anomaly_state);
        return 1;
    }

    /* Main event poll loop */
    while (!g_stop && (!tui || tui_is_running(tui))) {
        int res = coresentinel_engine_poll(engine, 100);
        if (res < 0 && res != -EINTR) {
            if (cfg.verbose) {
                fprintf(stderr, "Error polling eBPF ring buffer: %d\n", res);
            }
            break;
        }
    }

    /* Graceful cleanup */
    if (tui) {
        tui_stop(tui);
    }
    printf("\n[CoreSentinel] Shutting down eBPF engine...\n");
    coresentinel_engine_stop(engine);
    coresentinel_engine_destroy(engine);

    if (metrics_srv) {
        metrics_server_stop(metrics_srv);
    }
    anomaly_state_free(anomaly_state);

    printf("[CoreSentinel] Cleanup complete. Goodbye!\n");
    return 0;
}
