#ifndef __CORESENTINEL_METRICS_H__
#define __CORESENTINEL_METRICS_H__

#include "coresentinel/anomaly.h"
#include <stdbool.h>

typedef struct metrics_server metrics_server_t;

metrics_server_t* metrics_server_start(int port, anomaly_state_t *anomaly_state);
void metrics_server_stop(metrics_server_t *srv);

#endif /* __CORESENTINEL_METRICS_H__ */
