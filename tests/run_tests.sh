#!/usr/bin/env bash
set -euo pipefail

echo "=========================================="
echo "    Running CoreSentinel Test Suite       "
echo "=========================================="

mkdir -p build/tests

# Compile and run Anomaly tests
gcc -Wall -Wextra -O2 -I./include -I./bpf src/anomaly.c tests/test_anomaly.c -lpthread -o build/tests/test_anomaly
./build/tests/test_anomaly

# Compile and run Metrics tests
gcc -Wall -Wextra -O2 -I./include -I./bpf src/anomaly.c src/metrics.c tests/test_metrics.c -lpthread -o build/tests/test_metrics
./build/tests/test_metrics

# Compile and run Config tests
gcc -Wall -Wextra -O2 -I./include -I./bpf src/config.c tests/test_config.c -o build/tests/test_config
./build/tests/test_config

# Compile and run TUI & Feed tests
gcc -Wall -Wextra -O2 -I./include -I./bpf -D_DEFAULT_SOURCE -D_XOPEN_SOURCE=600 src/anomaly.c src/tui.c tests/test_tui.c -lpthread -lncursesw -o build/tests/test_tui
./build/tests/test_tui

echo "=========================================="
echo "    All CoreSentinel Tests Passed (100%)  "
echo "=========================================="
