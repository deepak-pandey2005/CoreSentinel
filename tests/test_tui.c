#include "coresentinel/anomaly.h"
#include "coresentinel/tui.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

void test_tui_null_safety(void) {
    assert(tui_is_running(NULL) == false);
    tui_stop(NULL);
    assert(tui_start(NULL, 9102) == NULL);
    printf("✓ test_tui_null_safety passed\n");
}

void test_anomaly_file_integrity_feed(void) {
    anomaly_state_t *st = anomaly_state_init();
    assert(st != NULL);

    struct sentinel_event e;
    memset(&e, 0, sizeof(e));
    e.event_type = EVENT_FILE_OPEN;
    e.severity = SENTINEL_SEV_HIGH;
    e.pid = 4321;
    e.uid = 0;
    strncpy(e.comm, "touch", sizeof(e.comm) - 1);
    strncpy(e.file_path, "/etc/pam.d/su", sizeof(e.file_path) - 1);
    e.is_write_access = 1;
    e.is_sensitive_file = 1;
    strncpy(e.alert_msg, "Modification of authentication security config /etc/pam.d/su", sizeof(e.alert_msg) - 1);

    anomaly_record_event(st, &e);

    assert(st->total_file_opens == 1);
    assert(st->file_count == 1);
    assert(st->total_alerts == 1);
    assert(st->alert_count == 1);
    assert(strcmp(st->recent_files[0].file_path, "/etc/pam.d/su") == 0);
    assert(st->recent_files[0].is_sensitive_file == 1);

    anomaly_state_free(st);
    printf("✓ test_anomaly_file_integrity_feed passed\n");
}

int main(void) {
    printf("Running CoreSentinel TUI & Data Feed Tests...\n");
    test_tui_null_safety();
    test_anomaly_file_integrity_feed();
    printf("All TUI & Data Feed Tests Passed!\n");
    return 0;
}
