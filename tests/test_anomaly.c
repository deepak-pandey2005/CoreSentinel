#include "coresentinel/anomaly.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

void test_anomaly_state_initialization(void) {
    anomaly_state_t *st = anomaly_state_init();
    assert(st != NULL);
    assert(st->total_events == 0);
    assert(st->total_alerts == 0);
    assert(st->exec_count == 0);
    assert(st->conn_count == 0);
    assert(st->alert_count == 0);
    assert(st->file_count == 0);
    anomaly_state_free(st);
    printf("✓ test_anomaly_state_initialization passed\n");
}

void test_anomaly_record_events(void) {
    anomaly_state_t *st = anomaly_state_init();
    assert(st != NULL);

    // 1. Record normal exec
    struct sentinel_event e1;
    memset(&e1, 0, sizeof(e1));
    e1.event_type = EVENT_EXEC;
    e1.severity = SENTINEL_SEV_INFO;
    e1.pid = 1234;
    e1.uid = 1000;
    strncpy(e1.comm, "ls", sizeof(e1.comm) - 1);
    strncpy(e1.filename, "/usr/bin/ls", sizeof(e1.filename) - 1);
    anomaly_record_event(st, &e1);

    assert(st->total_events == 1);
    assert(st->total_execs == 1);
    assert(st->total_alerts == 0);
    assert(st->exec_count == 1);
    assert(strcmp(st->recent_execs[0].comm, "ls") == 0);

    // 2. Record suspicious connection (Severity HIGH -> triggers alert)
    struct sentinel_event e2;
    memset(&e2, 0, sizeof(e2));
    e2.event_type = EVENT_CONNECT;
    e2.severity = SENTINEL_SEV_HIGH;
    e2.pid = 5555;
    e2.dport = 4444; // Metasploit port
    strncpy(e2.comm, "rev_shell", sizeof(e2.comm) - 1);
    strncpy(e2.alert_msg, "Outbound connection to known C2 / hacker backdoor port", sizeof(e2.alert_msg) - 1);
    anomaly_record_event(st, &e2);

    assert(st->total_events == 2);
    assert(st->total_connects == 1);
    assert(st->total_alerts == 1);
    assert(st->alert_count == 1);
    assert(st->recent_alerts[0].dport == 4444);
    assert(st->alerts_by_sev[SENTINEL_SEV_HIGH] == 1);

    // 3. Record sensitive file write attempt (Severity CRITICAL)
    struct sentinel_event e3;
    memset(&e3, 0, sizeof(e3));
    e3.event_type = EVENT_FILE_OPEN;
    e3.severity = SENTINEL_SEV_CRITICAL;
    e3.pid = 9999;
    strncpy(e3.comm, "malware", sizeof(e3.comm) - 1);
    strncpy(e3.file_path, "/etc/shadow", sizeof(e3.file_path) - 1);
    e3.is_write_access = 1;
    e3.is_sensitive_file = 1;
    strncpy(e3.alert_msg, "CRITICAL: Write/modification attempt on protected system file", sizeof(e3.alert_msg) - 1);
    anomaly_record_event(st, &e3);

    assert(st->total_events == 3);
    assert(st->total_file_opens == 1);
    assert(st->file_count == 1);
    assert(strcmp(st->recent_files[0].file_path, "/etc/shadow") == 0);
    assert(st->total_alerts == 2);
    assert(st->alert_count == 2);
    assert(st->alerts_by_sev[SENTINEL_SEV_CRITICAL] == 1);

    anomaly_state_free(st);
    printf("✓ test_anomaly_record_events passed\n");
}

void test_severity_and_event_strings(void) {
    assert(strcmp(sentinel_severity_str(SENTINEL_SEV_INFO), "INFO") == 0);
    assert(strcmp(sentinel_severity_str(SENTINEL_SEV_CRITICAL), "CRITICAL") == 0);
    assert(strcmp(sentinel_event_type_str(EVENT_EXEC), "EXEC") == 0);
    assert(strcmp(sentinel_event_type_str(EVENT_CONNECT), "CONNECT") == 0);
    assert(strcmp(sentinel_event_type_str(EVENT_FILE_OPEN), "FILE_OPEN") == 0);
    assert(strcmp(sentinel_event_type_str(EVENT_PRIV_ESC), "PRIV_ESC") == 0);
    printf("✓ test_severity_and_event_strings passed\n");
}

int main(void) {
    printf("Running CoreSentinel Anomaly Tests...\n");
    test_anomaly_state_initialization();
    test_anomaly_record_events();
    test_severity_and_event_strings();
    printf("All Anomaly Tests Passed!\n");
    return 0;
}
