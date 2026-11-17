#include "coresentinel/config.h"
#include "coresentinel.h"
#include <string.h>

void coresentinel_config_default(coresentinel_config_t *cfg) {
    if (!cfg) return;
    memset(cfg, 0, sizeof(*cfg));
    cfg->enable_tui = true;
    cfg->enable_metrics = true;
    cfg->metrics_port = 9102;
    cfg->min_alert_severity = SENTINEL_SEV_MEDIUM;
    strncpy(cfg->log_file, "coresentinel.log", sizeof(cfg->log_file) - 1);
    cfg->verbose = false;
}
