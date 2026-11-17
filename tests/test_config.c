#include "coresentinel/config.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

void test_default_config(void) {
    coresentinel_config_t cfg;
    coresentinel_config_default(&cfg);

    assert(cfg.enable_tui == true);
    assert(cfg.enable_metrics == true);
    assert(cfg.metrics_port == 9102);
    assert(strcmp(cfg.log_file, "coresentinel.log") == 0);
    assert(cfg.verbose == false);

    printf("✓ test_default_config passed\n");
}

int main(void) {
    printf("Running CoreSentinel Config Tests...\n");
    test_default_config();
    printf("All Config Tests Passed!\n");
    return 0;
}
