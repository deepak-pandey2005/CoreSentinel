#ifndef __CORESENTINEL_CONFIG_H__
#define __CORESENTINEL_CONFIG_H__

#include <stdbool.h>

typedef struct {
    bool enable_tui;
    bool enable_metrics;
    int metrics_port;
    int min_alert_severity;
    char log_file[256];
    bool verbose;
} coresentinel_config_t;

void coresentinel_config_default(coresentinel_config_t *cfg);

#endif /* __CORESENTINEL_CONFIG_H__ */
