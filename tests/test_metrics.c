#include "coresentinel/metrics.h"
#include <arpa/inet.h>
#include <assert.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

void test_metrics_http_endpoint(void) {
    anomaly_state_t *st = anomaly_state_init();
    assert(st != NULL);

    struct sentinel_event e1;
    memset(&e1, 0, sizeof(e1));
    e1.event_type = EVENT_EXEC;
    e1.severity = SENTINEL_SEV_HIGH;
    e1.pid = 4321;
    strncpy(e1.comm, "bad_actor", sizeof(e1.comm) - 1);
    strncpy(e1.alert_msg, "Suspicious execution", sizeof(e1.alert_msg) - 1);
    anomaly_record_event(st, &e1);

    int test_port = 9199;
    metrics_server_t *srv = metrics_server_start(test_port, st);
    assert(srv != NULL);

    usleep(50000); // Wait 50ms for listener to bind

    // Connect to /metrics
    int client = socket(AF_INET, SOCK_STREAM, 0);
    assert(client >= 0);

    struct sockaddr_in srv_addr;
    memset(&srv_addr, 0, sizeof(srv_addr));
    srv_addr.sin_family = AF_INET;
    srv_addr.sin_port = htons(test_port);
    inet_pton(AF_INET, "127.0.0.1", &srv_addr.sin_addr);

    int err = connect(client, (struct sockaddr*)&srv_addr, sizeof(srv_addr));
    assert(err == 0);

    const char *req = "GET /metrics HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n";
    write(client, req, strlen(req));

    char resp[8192];
    memset(resp, 0, sizeof(resp));
    size_t total_read = 0;
    while (total_read < sizeof(resp) - 1) {
        ssize_t n = read(client, resp + total_read, sizeof(resp) - 1 - total_read);
        if (n <= 0) break;
        total_read += n;
    }
    close(client);

    assert(strstr(resp, "HTTP/1.1 200 OK") != NULL);
    assert(strstr(resp, "coresentinel_events_total 1") != NULL);
    assert(strstr(resp, "coresentinel_exec_events_total 1") != NULL);
    assert(strstr(resp, "coresentinel_alerts_total 1") != NULL);
    assert(strstr(resp, "coresentinel_alerts_total{severity=\"high\"} 1") != NULL);

    // Check /healthz
    int h_client = socket(AF_INET, SOCK_STREAM, 0);
    assert(h_client >= 0);
    err = connect(h_client, (struct sockaddr*)&srv_addr, sizeof(srv_addr));
    assert(err == 0);
    const char *h_req = "GET /healthz HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n";
    write(h_client, h_req, strlen(h_req));

    memset(resp, 0, sizeof(resp));
    ssize_t n = read(h_client, resp, sizeof(resp) - 1);
    assert(n > 0);
    close(h_client);

    assert(strstr(resp, "HTTP/1.1 200 OK") != NULL);
    assert(strstr(resp, "OK\n") != NULL);

    metrics_server_stop(srv);
    anomaly_state_free(st);
    printf("✓ test_metrics_http_endpoint passed\n");
}

int main(void) {
    printf("Running CoreSentinel Metrics Tests...\n");
    test_metrics_http_endpoint();
    printf("All Metrics Tests Passed!\n");
    return 0;
}
