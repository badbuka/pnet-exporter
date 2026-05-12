# pnet-exporter

Prometheus exporter for Podman container network visibility, backed by eBPF.

The repository uses a flat Go layout: `main.go` at the root, runtime code under
`internal/`, eBPF C sources under `bpf/`.

## Quick Start

### Requirements

- Linux kernel 5.8+ with eBPF support (`CONFIG_BPF_SYSCALL`, `CONFIG_SCHEDSTATS` for delay accounting)
- Podman running on the host
- Root or capabilities: `CAP_BPF`, `CAP_PERFMON`, `CAP_NET_ADMIN`, `CAP_SYS_ADMIN`

### Run with Docker / Podman

```sh
podman run -d \
  --name pnet-exporter \
  --privileged \
  --pid=host \
  --network=host \
  -v /run/podman/podman.sock:/run/podman/podman.sock \
  -v /sys:/sys:ro \
  -v /proc:/proc:ro \
  badbuka/pnet-exporter:latest
```

Verify:

```sh
curl http://localhost:9108/healthz
curl http://localhost:9108/metrics
```

### Build and run from source

```sh
# Requires clang, bpftool, and a kernel with /sys/kernel/btf/vmlinux
make bpf build
sudo ./pnet-exporter
```

Metrics are served at `http://localhost:9108/metrics`.

## Configuration

All configuration is via environment variables with the `PNET_` prefix.

### General

| Variable | Default | Description |
|---|---|---|
| `PNET_LISTEN_ADDRESS` | `:9108` | Prometheus HTTP listen address |
| `PNET_LOG_LEVEL` | `info` | Log verbosity: `debug`, `info`, `warn`, `error` |
| `PNET_SHUTDOWN_TIMEOUT` | `10s` | Graceful HTTP shutdown timeout |
| `PNET_BPF_DIR` | `./bpf` | Directory containing compiled `.bpf.o` objects |
| `PNET_RING_BUFFER_SIZE` | `1048576` | BPF ring buffer size hint (bytes) |
| `PNET_SYSFS` | `/sys` | sysfs root (used by startup checks) |
| `PNET_PROCFS` | `/proc` | procfs root (used by node and delay collectors) |

### Podman discovery

| Variable | Default | Description |
|---|---|---|
| `PNET_PODMAN_SOCKET` | `/run/podman/podman.sock` | Podman API socket path |
| `PNET_PODMAN_BINARY` | `podman` | Podman CLI binary (fallback when socket is unavailable) |
| `PNET_DISCOVERY_INTERVAL` | `10s` | How often the container list is refreshed from Podman |
| `PNET_CONTAINER_TTL` | `1m` | How long the identity cache retains a container after Podman stops reporting it |

### Feature flags

| Variable | Default | Description |
|---|---|---|
| `PNET_FEATURE_NETWORK` | `true` | TCP connect/close/bytes/retransmit metrics |
| `PNET_FEATURE_DNS` | `true` | DNS request metrics |
| `PNET_FEATURE_HTTP` | `true` | HTTP request metrics and latency histograms |
| `PNET_FEATURE_POSTGRES` | `true` | Postgres query metrics |
| `PNET_FEATURE_REDIS` | `true` | Redis query metrics |
| `PNET_FEATURE_KAFKA` | `true` | Kafka request metrics |
| `PNET_FEATURE_LATENCY` | `false` | Per-container ICMP RTT probing |
| `PNET_FEATURE_NODE_METRICS` | `true` | Host-level CPU / memory / disk / network metrics from `/proc` |
| `PNET_FEATURE_DELAY_ACCOUNTING` | `true` | Per-container CPU and disk I/O wait counters from `/proc/<pid>/schedstat` |
| `PNET_FEATURE_OOM` | `true` | Container OOM-kill counter |

### Metrics tuning

| Variable | Default | Description |
|---|---|---|
| `PNET_METRIC_TTL` | `10m` | TTL for momentary series (active connections, latency, histograms, IP→FQDN). Counters are kept until the container disappears. |
| `PNET_CLEANUP_INTERVAL` | `1m` | How often the janitor prunes expired series |
| `PNET_MAX_DESTINATIONS_PER_CONTAINER` | `512` | Max distinct destination labels per container; excess values become `~other` |
| `PNET_MAX_FQDNS_PER_CONTAINER` | `100` | Max distinct FQDN labels per container; excess values become `~other` |
| `PNET_DURATION_BUCKETS` | `0.005,0.01,0.025,0.05,0.1,0.25,0.5,1,2.5,5,10` | Histogram bucket boundaries for L7 request durations (seconds, comma-separated) |
| `PNET_DNS_DURATION_BUCKETS` | `0.001,0.0025,0.005,0.01,0.025,0.05,0.1,0.25,0.5` | Histogram bucket boundaries for DNS request durations (seconds, comma-separated) |

### ICMP latency prober (`PNET_FEATURE_LATENCY=true`)

| Variable | Default | Description |
|---|---|---|
| `PNET_LATENCY_INTERVAL` | `30s` | How often ICMP probes are sent per container |
| `PNET_LATENCY_TIMEOUT` | `1s` | Probe timeout |
| `PNET_LATENCY_MAX_TARGETS` | `100` | Max destinations probed per container per interval |

### Delay accounting (`PNET_FEATURE_DELAY_ACCOUNTING=true`)

| Variable | Default | Description |
|---|---|---|
| `PNET_DELAY_INTERVAL` | `15s` | How often `/proc/<pid>/schedstat` is read per container |

## Building

```sh
make test           # Go unit tests
make lint           # golangci-lint
make ci             # lint + test
make bpf            # build BPF objects locally (requires bpftool + clang)
make build          # build pnet-exporter (with version stamping)
make docker-build   # multi-arch image build
```

Integration tests that require Podman live behind the `integration` build tag:

```sh
make test-integration
```

## Architecture

```
                +----------------------+      +-------------------------+
podman ps ----> |  identity.Cache      |<---->|  ebpf.Loader            |
                |  (PID/cgroup index)  |      |  - tcp_state.bpf        |
                +----------------------+      |  - tcp_retransmit.bpf   |
                                              |  - tcp_bytes.bpf        |
                                              |  - tcp_conntrack.bpf    |
                                              |  - l7.bpf               |
                                              |  - dns.bpf              |
                                              |  - oom.bpf              |
                                              +-----------+-------------+
                                                          | ringbuf events
                +-----------------+        +---------------v---------------+
                |  store.Store    |<-------|  dispatch / NAT cache         |
                |  (Prometheus    |        +--------------+----------------+
                |   snapshots)    |                       |
                +--------+--------+                       |
                         |                                v
                         |              +------------------------------+
                         +<-------------|  prober (ICMP, setns)         |
                         +<-------------|  delays (taskstats / schedstat)|
                         +<-------------|  node (/proc cpu/mem/disk/net)|
                         +<-------------|  protocol parsers (HTTP, ...)  |
                         |              +------------------------------+
                +--------v---------+
                | collector.* +    |
                | /metrics handler |
                +------------------+
```

The BPF layer pushes typed events (`tcp_event`, `nat_event`, `l7_event`,
`dns_event`, `oom_event`) through a single ringbuf. Userspace dispatches by
the first byte (`kind`) and routes into the store. The NAT cache makes
post-DNAT destinations available as `actual_destination` labels.

## Metrics

All metrics include the `node_hostname` label. Container-scoped metrics
additionally include `container_id`, `container_name`, and `pod_id`.
Destination label values are bounded per container by
`PNET_MAX_DESTINATIONS_PER_CONTAINER`; overflow values become `~other`.

### TCP

- `container_net_tcp_listen_info` gauge: labels `listen_addr`, `proxy`.
- `container_net_tcp_successful_connects_total` counter.
- `container_net_tcp_failed_connects_total` counter.
- `container_net_tcp_retransmits_total` counter.
- `container_net_tcp_active_connections` gauge. Incremented on
  `SYN_SENT → ESTABLISHED` and decremented on `ESTABLISHED → CLOSE` for
  sockets the kernel tracked via the outbound-socket map.
- `container_net_tcp_bytes_sent_total` counter, sourced from kprobe
  `tcp_sendmsg`.
- `container_net_tcp_bytes_received_total` counter, sourced from kprobe
  `tcp_cleanup_rbuf`.
- `container_net_latency_seconds` gauge: ICMP RTT measured inside the
  container's network namespace.
- `ip_to_fqdn` gauge: labels `ip`, `fqdn`.

### Application protocols (L7)

Driven by the `l7.bpf.o` kprobes on `tcp_sendmsg`/`tcp_recvmsg` plus
parsers in `internal/protocol/`. Status values are bounded to
`ok|error|timeout|unknown` (HTTP retains the raw status code).

- `container_http_requests_total`, `container_http_requests_duration_seconds_*`.
- `container_postgres_queries_total`, `container_postgres_queries_duration_seconds_*`.
- `container_redis_queries_total`, `container_redis_queries_duration_seconds_*`.
- `container_kafka_requests_total`, `container_kafka_requests_duration_seconds_*`.

### DNS

Driven by `dns.bpf.o` (kprobes on `udp_sendmsg`/`udp_recvmsg`) plus a
small DNS parser in `internal/protocol/dns.go`.

- `container_dns_requests_total`: labels `domain`, `request_type`, `status`.
- `container_dns_requests_duration_seconds_*` histogram.

### Runtime

- `container_oom_kills_total`: kprobe on `oom_kill_process`.
- `container_resources_cpu_delay_seconds_total`: aggregated from
  `/proc/<pid>/schedstat` (runqueue wait time per cgroup).
- `container_resources_disk_delay_seconds_total`: derived from
  `delayacct_blkio_ticks` in `/proc/<pid>/stat`.

### Node

When `PNET_FEATURE_NODE_METRICS=true` (default), the exporter also emits
host-level metrics scraped from `/proc`:

- `node_cpu_seconds_total{mode}`, `node_memory_*_bytes`, `node_uptime_seconds`.
- `node_disk_{reads,writes,read_bytes,written_bytes}_total{device}`.
- `node_network_{receive,transmit}_{bytes,errors}_total{interface}`.

### Build info

- `pnet_exporter_build_info` gauge: labels `version`, `commit`, `go_version`.

## Design choices

- Discovery is Podman-only (no docker/containerd/CRI-O integrations).
- L7 protocols are classified and parsed in Go from captured payloads; BPF
  only gathers bytes and socket tuples.
- The in-memory metric store uses flat maps keyed by label sets rather than
  a per-container subtree; this keeps the codebase small for Podman-sized
  deployments.

BPF programs live under [`bpf/`](bpf/) (TCP lifecycle, NAT, L7 payloads,
UDP/DNS, OOM); userspace dispatches ringbuf records in [`internal/ebpf`](internal/ebpf).
