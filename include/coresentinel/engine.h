#ifndef __CORESENTINEL_ENGINE_H__
#define __CORESENTINEL_ENGINE_H__

#include "coresentinel/config.h"
#include "coresentinel/anomaly.h"
#include <stdbool.h>

typedef struct coresentinel_engine coresentinel_engine_t;

coresentinel_engine_t* coresentinel_engine_create(const coresentinel_config_t *cfg, anomaly_state_t *state);
int coresentinel_engine_start(coresentinel_engine_t *eng);
int coresentinel_engine_poll(coresentinel_engine_t *eng, int timeout_ms);
void coresentinel_engine_stop(coresentinel_engine_t *eng);
void coresentinel_engine_destroy(coresentinel_engine_t *eng);

#endif /* __CORESENTINEL_ENGINE_H__ */
