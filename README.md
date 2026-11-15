<div align="center">

# Knet Tracer | Linux eBPF Network Observability and Kernel Telemetry in Go

Knet Tracer is a Go-based Linux network observability project that uses eBPF hooks to collect kernel-level network telemetry. The README describes tracing through kprobes, tracepoints, and traffic-control hooks, with metrics exposed for monitoring systems such as Prometheus and OpenTelemetry. It is relevant to SREs and systems developers investigating packet paths, TCP behavior, drops, and network performance on Linux.


### **Distributed eBPF Observability & Kernel Network Telemetry Engine**

[![CI Pipeline](https://github.com/ER-brocode/knet-tracer/actions/workflows/ci.yml/badge.svg)](https://github.com/ER-brocode/knet-tracer/actions/workflows/ci.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/ER-brocode/knet-tracer)](https://goreportcard.com/report/github.com/ER-brocode/knet-tracer)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![eBPF](https://img.shields.io/badge/eBPF-TC%20%7C%20Kprobe%20%7C%20Tracepoint-orange.svg)](https://ebpf.io)
[![Telemetry](https://img.shields.io/badge/Telemetry-Prometheus%20%7C%20OTLP-green.svg)](https://opentelemetry.io)

```
  ┌────────────────────────────────────────────────────────────────────────┐
  │                           LINUX KERNEL SPACE                           │
  │                                                                        │
  │   [kprobe/tcp_rcv_established]     [tracepoint/skb/kfree_skb]          │
  │                │                                │                      │
  │                ▼                                ▼                      │
  │         [TCP SRTT / CWND]               [Drop Reason Tracker]          │
  │                │                                │                      │
  │                └───────────────┬────────────────┘                      │
  │                                │                                       │
  │                                ▼                                       │
  │                  BPF RingBuffer (16MB Lockless)                        │
  └────────────────────────────────┬───────────────────────────────────────┘
                                   │ Zero-Copy Ingest
  ┌────────────────────────────────▼───────────────────────────────────────┐
  │                          USERSPACE AGENT                               │
  │                                                                        │
  │                 knet-tracer Streaming Collector                        │
  │                                │                                       │
  │               Per-Flow State Machine & Aggregator                      │
  │                                │                                       │
  │                 ┌──────────────┴──────────────┐                        │
  │                 ▼                             ▼                        │
  │        Prometheus Exporter            OpenTelemetry (OTLP)             │
  │          (:9102/metrics)                 Metric Stream                 │
  └────────────────────────────────────────────────────────────────────────┘
```

</div>

---

## 🚀 Overview

`knet-tracer` is a high-performance distributed eBPF kernel network telemetry engine engineered for low-overhead, nanosecond-precision microservice observability. By hooking into deep Linux network stack functions (`tcp_rcv_established`, `skb:kfree_skb`, and Traffic Control classifiers), `knet-tracer` uncovers granular network performance insights without sidecar injection, proxy overhead, or application modifications.

### Key Capabilities

- **Zero-Overhead TCP RTT Tracking**: Measures true kernel-level smoothed RTT (`srtt_us`), variance, and minimum RTT directly from `struct tcp_sock` in nanoseconds.
- **Microsecond Packet Drop Diagnosis**: Intercepts `kfree_skb` with drop reasons (e.g., checksum error, buffer exhaustion, TCP reset, netfilter rejection) and PC callsite addresses.
- **Congestion & Buffer Monitoring**: Extracts real-time congestion window (`snd_cwnd`), slow-start threshold (`snd_ssthresh`), socket send/receive buffer pressures, and retransmit counters.
- **Dual Exporter Architecture**:
  - Native **Prometheus** pull exporter with metric histograms and labeled counters at `/metrics`.
  - **OpenTelemetry (OTLP)** push pipeline delivering metrics directly to OpenTelemetry Collectors, Datadog, or Grafana Mimir.
- **Simulation Harness**: Built-in synthetic telemetry generator enabling end-to-end integration testing and development on any operating system without requiring root eBPF privileges.

---

## 📊 Telemetry Metrics Catalog

| Metric Name | Type | Labels | Description |
|---|---|---|---|
| `knet_tcp_rtt_microseconds` | Histogram | `src_ip`, `dst_ip`, `dst_port`, `comm` | TCP smoothed round-trip time measured at kernel level |
| `knet_packet_drops_total` | Counter | `src_ip`, `dst_ip`, `reason`, `proto` | Kernel-dropped packets by reason (`TCP_RESET`, `QUEUE_PURGE`, etc.) |
| `knet_tcp_congestion_window_segments` | Gauge | `src_ip`, `dst_ip`, `dst_port` | TCP Congestion Window size (`snd_cwnd`) in segments |
| `knet_tcp_retransmissions_total` | Counter | `src_ip`, `dst_ip`, `dst_port` | Cumulative retransmitted packets per active flow |
| `knet_flow_bytes_acked_total` | Counter | `src_ip`, `dst_ip`, `dst_port` | Cumulative bytes acknowledged across active TCP connection |
| `knet_engine_active_tracked_flows` | Gauge | — | Total count of actively monitored concurrent network flows |

---

## 🏗️ Architecture & eBPF Hookpoints

### 1. Kprobe: `tcp_rcv_established`
Attached to TCP's fast-path packet reception handler. Whenever a packet is acknowledged on an established connection, the probe reads `tp->srtt_us`, `tp->mdev_us`, `tp->snd_cwnd`, and `tp->total_retrans` and dispatches records through a 16MB eBPF ring buffer.

### 2. Tracepoint: `skb:kfree_skb`
Captures every packet dropped across the kernel stack, extracting network protocol headers, drop reasons, and calling functions with built-in LRU rate-limiting to prevent userspace event floods.

### 3. TC (Traffic Control) Classifiers: `tc_ingress` & `tc_egress`
Attaches directly to the network interface qdisc to record wire-level raw packet lengths and ingress/egress bandwidth counters before socket delivery.

---

## ⚡ Quickstart

### Prerequisites
- Linux Kernel >= 5.8 with `CONFIG_DEBUG_INFO_BTF=y` (for live eBPF probing)
- Go >= 1.22
- Clang / LLVM >= 14 (for building eBPF bytecode)

### Installation & Run

```bash
# Clone the repository
git clone https://github.com/ER-brocode/knet-tracer.git
cd knet-tracer

# Build the daemon
go build -o bin/knet-tracer ./cmd/knet-tracer

# Run with Prometheus metrics server on :9102
sudo ./bin/knet-tracer --metrics-addr=":9102"
```

### Running with OpenTelemetry OTLP Streaming

```bash
sudo ./bin/knet-tracer \
  --metrics-addr=":9102" \
  --otlp-endpoint="http://otel-collector.monitoring.svc:4318/v1/metrics"
```

### Running Simulation Mode (Dev / Test)

```bash
# Run without eBPF kernel capabilities on macOS, Windows, or non-Linux CI
go run ./cmd/knet-tracer --simulate --metrics-addr=":9102"
```

Verify metrics via curl:
```bash
curl http://localhost:9102/metrics
```

---

## 🧪 Testing & Validation

The test suite includes metric aggregation verification, synthetic eBPF ringbuffer stream validation, concurrent flow ingestion, TTL eviction, and mock OTLP server HTTP testing:

```bash
go test -v ./tests
```

```
=== RUN   TestMetricAggregationPipeline
    metric_collection_test.go:63: Successfully verified 10 concurrent active network flows
--- PASS: TestMetricAggregationPipeline (0.00s)
=== RUN   TestPacketDropAccounting
--- PASS: TestPacketDropAccounting (0.01s)
=== RUN   TestFlowEvictionTTL
--- PASS: TestFlowEvictionTTL (0.03s)
=== RUN   TestOTLPExporterIntegration
--- PASS: TestOTLPExporterIntegration (0.22s)
=== RUN   TestConcurrentIngestion
--- PASS: TestConcurrentIngestion (0.02s)
PASS
ok  	github.com/ER-brocode/knet-tracer/tests	0.322s
```

---

## 👥 Authors & License

Maintained by **[koushik4475](https://github.com/koushik4475)** (`koushik4475@gmail.com`).  
Licensed under the [Apache License, Version 2.0](LICENSE).
