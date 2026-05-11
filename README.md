# pnet-exporter

Prometheus exporter for Podman container network visibility, backed by eBPF.

The repository uses a flat Go layout: `main.go` at the root, runtime code under
`internal/`, eBPF C sources under `bpf/`.

## Configuration

Configuration is loaded from environment variables with the `PNET_` prefix.

- `PNET_LISTEN_ADDRESS`: Prometheus HTTP listen address, default `:9108`.
- `PNET_LOG_LEVEL`: `debug`, `info`, `warn`, or `error`, default `info`.
- `PNET_PODMAN_SOCKET`: Podman API socket path, default `/run/podman/podman.sock`.
- `PNET_PODMAN_BINARY`: Podman CLI fallback binary, default `podman`.
- `PNET_DISCOVERY_INTERVAL`: Podman discovery refresh interval, default `10s`.
- `PNET_SHUTDOWN_TIMEOUT`: graceful HTTP shutdown timeout, default `10s`.
- `PNET_CONTAINER_TTL`: how long the identity cache keeps a container after
  Podman stops reporting it, default `1m`.
- `PNET_SYSFS`, `PNET_PROCFS`: sysfs/procfs roots used by startup checks and
  the node-runtime collector. Defaults `/sys`, `/proc`.
- `PNET_FEATURE_NETWORK`, `PNET_FEATURE_DNS`, `PNET_FEATURE_HTTP`,
  `PNET_FEATURE_POSTGRES`, `PNET_FEATURE_REDIS`, `PNET_FEATURE_KAFKA`: feature
  toggles, default `true`.
- `PNET_FEATURE_LATENCY`: per-container ICMP probing, default `false`.
- `PNET_FEATURE_NODE_METRICS`: node-level `/proc` collectors, default `true`.
- `PNET_FEATURE_DELAY_ACCOUNTING`: per-container schedstat-driven CPU/IO delay
  counters, default `true`.
- `PNET_FEATURE_OOM`: container OOM-kill counter, default `true`.
- `PNET_MAX_DESTINATIONS_PER_CONTAINER`, `PNET_MAX_FQDNS_PER_CONTAINER`:
  cardinality limits.
- `PNET_METRIC_TTL`: TTL for *momentary* series (active connections, latency,
  histograms, IP→FQDN); counter series are pruned only when their container
  disappears, to preserve counter monotonicity.
- `PNET_CLEANUP_INTERVAL`: how often the janitor runs.
- `PNET_DURATION_BUCKETS`, `PNET_DNS_DURATION_BUCKETS`: comma-separated
  Prometheus histogram buckets in seconds.
- `PNET_LATENCY_INTERVAL`, `PNET_LATENCY_TIMEOUT`, `PNET_LATENCY_MAX_TARGETS`:
  ICMP prober tuning.
- `PNET_DELAY_INTERVAL`: how often per-container CPU/disk delay counters are
  scraped from `/proc/<pid>/schedstat` and `/proc/<pid>/stat`.
- `PNET_BPF_DIR`: directory containing compiled eBPF objects, default `./bpf`.
- `PNET_RING_BUFFER_SIZE`: hint for the BPF ring buffer size, default `1048576`.

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
