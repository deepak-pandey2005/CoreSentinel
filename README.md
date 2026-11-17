# CoreSentinel: eBPF Linux Kernel Security & Observability Engine

**CoreSentinel** is a high-performance, kernel-native security, safety, and observability engine written in C using **eBPF CO-RE (Compile Once – Run Everywhere)** with `libbpf` and `bpftool`.

It monitors system activity at kernel execution boundaries with negligible overhead, detecting malicious behaviors (reverse shells, privilege escalation, credential theft, C2 egress) and exposing real-time ANSI terminal telemetry and Prometheus metrics.

---

## Architecture Overview

```
                          ┌──────────────────────────────────────────────┐
                          │            Linux Kernel Space                │
                          │                                              │
                          │  tracepoint/syscalls/sys_enter_execve        │
                          │  tracepoint/syscalls/sys_enter_setuid        │
                          │  tracepoint/syscalls/sys_enter_openat        │
                          │  tracepoint/syscalls/sys_enter_connect       │
                          │                                              │
                          │          BPF_MAP_TYPE_RINGBUF                │
                          └──────────────────────┬───────────────────────┘
                                                 │ Lockless RingBuffer
                                                 ▼
                          ┌──────────────────────────────────────────────┐
                          │           Userspace Control Plane            │
                          │               (CoreSentinel)                 │
                          │                                              │
                          │  • libbpf skeleton & ring_buffer__poll()     │
                          │  • Real-time Anomaly & Safety Engine         │
                          │  • ANSI Terminal Dashboard (TUI)             │
                          │  • Embedded Prometheus Metrics (/metrics)    │
                          │  • Security Event Logger (JSON/Text)         │
                          └──────────────────────────────────────────────┘
```

---

## Safety & Security Detection Rules

| Threat Vector | eBPF Hook | Detection Logic & Anomaly Rule | Severity |
|---|---|---|---|
| **Reverse Shells** | `sys_enter_execve` | Interactive shells (`sh`, `bash`, `zsh`) spawned by web/script engines (`nginx`, `apache`, `python`, `node`, `nc`). | `CRITICAL` |
| **Volatile Executions** | `sys_enter_execve` | Binaries spawned from writable/temp locations (`/tmp/`, `/dev/shm/`, `/var/tmp/`). | `HIGH` |
| **Privilege Escalation** | `sys_enter_setuid` | Non-root processes transitioning into UID 0 (`root`). | `CRITICAL` |
| **Sensitive File Tampering** | `sys_enter_openat` | Write, append, or truncate accesses (`O_WRONLY`, `O_RDWR`, `O_CREAT`) to `/etc/shadow`, `/etc/passwd`, `/etc/sudoers`, `/etc/ld.so.preload`. | `CRITICAL` |
| **Credential Surveillance** | `sys_enter_openat` | Read access to `/etc/shadow` or sensitive authentication configurations. | `MEDIUM` |
| **C2 Backdoors** | `sys_enter_connect` | Outbound TCP connections targeting known backdoor / C2 listener ports (`4444`, `1337`, `31337`, `6667`). | `HIGH` |

---

## Features

- **True eBPF CO-RE (Compile Once – Run Everywhere)**: Uses BTF (`vmlinux.h`) and `libbpf` for portable execution across modern Linux kernels.
- **Lockless Event Streaming**: Leverages `BPF_MAP_TYPE_RINGBUF` for memory-efficient, non-blocking telemetry from kernel to userspace.
- **Zero-Dependency ANSI Terminal Dashboard**: Live terminal UI displaying active executions, network connections, and security alerts.
- **Embedded Prometheus Metrics Exporter**: Built-in HTTP microserver on port `:9102` (`/metrics` and `/healthz`) for scraping by Prometheus or Grafana.
- **Headless Daemon Mode**: `--no-tui` option for running as a headless system service or inside containers.

---

## Quickstart

### Prerequisites

- Linux Kernel 5.8+ (BTF enabled at `/sys/kernel/btf/vmlinux`)
- `clang` & `llvm`
- `bpftool`
- `libbpf-dev` / `libbpf`, `libelf`, `zlib`

### Building

```bash
# Build the eBPF bytecode, generate skeleton, and compile CoreSentinel
make all
```

The resulting binary will be placed at `bin/coresentinel`.

### Running

Since eBPF kernel hooks require administrative privileges, run with `sudo`:

```bash
# Run with interactive ANSI TUI and Prometheus exporter
sudo ./bin/coresentinel

# Or run in headless mode with custom port and log file
sudo ./bin/coresentinel --no-tui --port 9102 --log /var/log/coresentinel.log
```

### Running Tests

```bash
make test
```

---

## Prometheus Metrics

Scrape `http://127.0.0.1:9102/metrics` to access operational telemetry:

```prometheus
# HELP coresentinel_events_total Total eBPF kernel security and observation events
# TYPE coresentinel_events_total counter
coresentinel_events_total 1420

# HELP coresentinel_exec_events_total Total process execution events
# TYPE coresentinel_exec_events_total counter
coresentinel_exec_events_total 312

# HELP coresentinel_connect_events_total Total outbound socket connect events
# TYPE coresentinel_connect_events_total counter
coresentinel_connect_events_total 890

# HELP coresentinel_file_open_events_total Total sensitive file open events
# TYPE coresentinel_file_open_events_total counter
coresentinel_file_open_events_total 218

# HELP coresentinel_alerts_total Total security anomaly alerts detected
# TYPE coresentinel_alerts_total counter
coresentinel_alerts_total 3
coresentinel_alerts_total{severity="critical"} 1
coresentinel_alerts_total{severity="high"} 2
```

---

## Project Structure

```
├── bpf/
│   ├── vmlinux.h               # Kernel BTF definitions
│   ├── coresentinel.bpf.c      # eBPF C kernel program
│   └── coresentinel.h          # Shared event structs & enums
├── include/
│   ├── coresentinel/
│   │   ├── anomaly.h           # Safety rule engine & bounded circular buffers
│   │   ├── config.h            # Configuration options
│   │   ├── engine.h            # Userspace libbpf skeleton lifecycle manager
│   │   ├── metrics.h           # Embedded Prometheus HTTP server
│   │   └── tui.h               # ANSI terminal dashboard
│   └── coresentinel.skel.h     # Autogenerated bpftool skeleton
├── src/
│   ├── anomaly.c               # Anomaly tracking & threat categorization
│   ├── config.c                # Default configuration initialization
│   ├── engine.c                # Ring buffer polling & event handling
│   ├── metrics.c               # Prometheus exporter microserver
│   ├── tui.c                   # Real-time ANSI terminal UI
│   └── main.c                  # CLI entry point and signal handling
├── tests/
│   ├── test_anomaly.c          # Unit tests for anomaly engine
│   ├── test_config.c           # Unit tests for configuration
│   ├── test_metrics.c          # Unit tests for Prometheus HTTP endpoint
│   └── run_tests.sh            # Automated test runner script
├── Makefile                    # Modular build system
└── README.md                   # Documentation
```
