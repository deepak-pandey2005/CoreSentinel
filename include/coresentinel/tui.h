#ifndef __CORESENTINEL_TUI_H__
#define __CORESENTINEL_TUI_H__

#include "coresentinel/anomaly.h"
#include <stdbool.h>

typedef struct tui_dashboard tui_dashboard_t;

tui_dashboard_t* tui_start(anomaly_state_t *state, int metrics_port);
void tui_stop(tui_dashboard_t *tui);

#endif /* __CORESENTINEL_TUI_H__ */
