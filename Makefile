CC ?= clang
BPF_CLANG ?= clang
BPFTOOL ?= bpftool

CFLAGS ?= -Wall -Wextra -O2 -g -I./include -I./bpf -D_DEFAULT_SOURCE -D_XOPEN_SOURCE=600
LDFLAGS ?= -lbpf -lelf -lz -lpthread -lncursesw

BPF_CFLAGS := -g -O2 -target bpf -D__TARGET_ARCH_x86 -Wno-missing-declarations -I/usr/include -I./bpf

SRC_FILES := src/config.c src/anomaly.c src/metrics.c src/tui.c src/engine.c src/main.c
OBJ_FILES := $(patsubst src/%.c, build/%.o, $(SRC_FILES))

BPF_SRC := bpf/coresentinel.bpf.c
BPF_OBJ := build/coresentinel.bpf.o
BPF_SKEL := include/coresentinel.skel.h

TARGET := bin/coresentinel

.PHONY: all clean run test

all: $(TARGET)

bpf/vmlinux.h:
	@mkdir -p bpf
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@

$(BPF_OBJ): $(BPF_SRC) bpf/coresentinel.h bpf/vmlinux.h | build
	$(BPF_CLANG) $(BPF_CFLAGS) -c $< -o $@

$(BPF_SKEL): $(BPF_OBJ) | include
	$(BPFTOOL) gen skeleton $< > $@

build/%.o: src/%.c $(BPF_SKEL) | build
	$(CC) $(CFLAGS) -c $< -o $@

$(TARGET): $(BPF_SKEL) $(OBJ_FILES) | bin
	$(CC) $(CFLAGS) $(OBJ_FILES) $(LDFLAGS) -o $@

build:
	@mkdir -p build

bin:
	@mkdir -p bin

include:
	@mkdir -p include

test: $(TARGET)
	@echo "Running CoreSentinel self-test..."
	@./tests/run_tests.sh

clean:
	rm -rf build bin include/coresentinel.skel.h coresentinel.log
