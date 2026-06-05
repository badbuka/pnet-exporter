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

`--pid=host` plus the `/proc` mount let the exporter discover containers for
every user on the host (rootful and rootless). To also enrich *rootless*
container names and pod IDs, additionally mount the user runtime sockets with
`-v /run/user:/run/user:ro` (matched by `PNET_PODMAN_USER_SOCKETS_GLOB`);
without them, rootless containers still appear, just keyed by container ID.

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

Container discovery is host-wide: a `/proc` cgroup scan is the source of truth
for which containers exist (it sees every rootful and rootless user's
containers), and the Podman REST API is used only to enrich names and pod IDs.
See [Container discovery](#container-discovery) for details.

| Variable | Default | Description |
|---|---|---|
| `PNET_PODMAN_SOCKET` | `/run/podman/podman.sock` | Root Podman API socket used for name/pod enrichment |
| `PNET_PODMAN_USER_SOCKETS_GLOB` | `/run/user/*/podman/podman.sock` | Glob of rootless user Podman sockets to also query for enrichment |
| `PNET_DISCOVERY_INTERVAL` | `10s` | How often the container list is refreshed |
| `PNET_CONTAINER_TTL` | `1m` | How long the identity cache retains a container after it stops being reported |

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
| `PNET_FEATURE_CONTAINER_RESOURCES` | `true` | Per-container CPU / memory / block-I/O / PSI pressure from cgroup v2 |

### Metrics tuning

| Variable | Default | Description |
|---|---|---|
| `PNET_METRIC_TTL` | `10m` | TTL for momentary series (active connections, latency, histograms, IP→FQDN). Counters are kept until the container disappears. |
| `PNET_CLEANUP_INTERVAL` | `1m` | How often the janitor prunes expired series |
| `PNET_MAX_DESTINATIONS_PER_CONTAINER` | `512` | Max distinct destination labels per container; excess values become `~other` |
| `PNET_MAX_FQDNS_PER_CONTAINER` | `100` | Max distinct FQDN labels per container; excess values become `~other` |
| `PNET_MAX_URLS_PER_CONTAINER` | `200` | Max distinct HTTP `url` labels per container; excess values become `~other` |
| `PNET_COLLAPSE_DYNAMIC_PORTS` | `true` | Collapse ephemeral-port `destination`/`actual_destination`/`source` labels: a port in the dynamic range is replaced with `dyn_ports` (e.g. `127.0.0.1:dyn_ports`), keeping all short-lived connections to a host in one series |
| `PNET_DYNAMIC_PORT_MIN` | `32768` | Lower bound (inclusive) of the dynamic port range collapsed into `dyn_ports` |
| `PNET_DYNAMIC_PORT_MAX` | `65535` | Upper bound (inclusive) of the dynamic port range collapsed into `dyn_ports` |
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

### Container resources (`PNET_FEATURE_CONTAINER_RESOURCES=true`)

| Variable | Default | Description |
|---|---|---|
| `PNET_RESOURCES_INTERVAL` | `15s` | How often cgroup v2 resource files are read per container |

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
 /proc cgroup scan  --+
 (all containers)     |        +----------------------+      +-------------------------+
                      +------> |  identity.Cache      |<---->|  ebpf.Loader            |
 Podman sockets  -----+        |  (PID/cgroup index)  |      |  - tcp_state.bpf        |
 (name/pod enrich)             +----------------------+      |  - tcp_retransmit.bpf   |
                                                             |  - tcp_bytes.bpf        |
                                                             |  - tcp_inbound.bpf      |
                                                             |  - tcp_conntrack.bpf    |
                                                             |  - l7.bpf               |
                                                             |  - dns.bpf              |
                                                             |  - oom.bpf              |
                                                             +-----------+-------------+
                                                                         | ringbuf events
                +-----------------+        +--------------------------------v--------------+
                |  store.Store    |<-------|  dispatch / NAT cache / flow protocol cache   |
                |  (Prometheus    |        +--------------+--------------------------------+
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
post-DNAT destinations available as `actual_destination` labels, and the flow
protocol cache remembers content-sniffed L7 verdicts per connection.

### Container discovery

Discovery runs every `PNET_DISCOVERY_INTERVAL` and has two stages
(`internal/podman/discovery.go`):

1. **`/proc` scan (source of truth).** Every `${PNET_PROCFS}/<pid>/cgroup` is
   read and matched against the Podman `libpod-<64-hex-id>` cgroup marker. This
   surfaces containers for *all* users - rootful and every rootless user -
   because it does not depend on any single user's Podman state. For each
   container the lowest PID is chosen and its cgroup inode (matching
   `bpf_get_current_cgroup_id()`) plus net/mnt namespace inodes are recorded.
2. **Socket enrichment.** The root socket (`PNET_PODMAN_SOCKET`) and every
   rootless socket matching `PNET_PODMAN_USER_SOCKETS_GLOB` are queried over the
   Podman REST API to fill in container `name` and `pod_id`. Unreachable sockets
   are skipped; a container still appears (keyed by ID) even when no socket
   reports it, just without a friendly name.

There is no dependency on the `podman` CLI binary.

## Metrics

All metrics include the `node_hostname` label. Container-scoped metrics
additionally include `container_id`, `container_name`, and `pod_id`.
Destination label values are bounded per container by
`PNET_MAX_DESTINATIONS_PER_CONTAINER`; overflow values become `~other`.
With `PNET_COLLAPSE_DYNAMIC_PORTS` enabled (the default), `destination`,
`actual_destination`, and `source` values whose port is in the dynamic
range collapse to `IP:dyn_ports` to keep ephemeral-port churn from
inflating cardinality.

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

#### Inbound (server-side) TCP

Driven by `tcp_inbound.bpf.o`, which tracks sockets returned by
`inet_csk_accept` (connections a server inside the container accepted).
These metrics carry a `source` label holding the remote client endpoint
(`IP:port`), bounded per container by `PNET_MAX_DESTINATIONS_PER_CONTAINER`
(overflow becomes `~other`). When `PNET_COLLAPSE_DYNAMIC_PORTS` is enabled
(the default), client endpoints whose port falls in the dynamic range
(`PNET_DYNAMIC_PORT_MIN`..`PNET_DYNAMIC_PORT_MAX`) are collapsed to
`IP:dyn_ports`, so per-connection ephemeral ports do not explode
cardinality. They are additive: server-side bytes also
still appear in the peer-labeled `container_net_tcp_bytes_*_total` totals
above; the inbound series provide the disambiguated server view by client.

- `container_net_tcp_inbound_accepts_total` counter: inbound connections
  accepted, sourced from kretprobe `inet_csk_accept`.
- `container_net_tcp_inbound_active_connections` gauge: incremented on
  accept and decremented on `tcp_close` for accepted sockets.
- `container_net_tcp_inbound_bytes_sent_total` counter: bytes the server
  sent on accepted connections.
- `container_net_tcp_inbound_bytes_received_total` counter: bytes the
  server received on accepted connections.

- `ip_to_fqdn` gauge: labels `ip`, `fqdn`.

### Application protocols (L7)

Driven by the `l7.bpf.o` kprobes on `tcp_sendmsg`/`tcp_recvmsg` plus
parsers in `internal/protocol/`. Status values are bounded to
`ok|error|timeout|unknown` (HTTP retains the raw status code).

Flows are classified by destination/source port first. When neither port is
registered, the captured payload is content-sniffed for HTTP: cleartext
HTTP/1.x (request/status lines) and HTTP/2 over cleartext (h2c connection
preface and HPACK `:status`) are detected on *any* port, so HTTP traffic is
discovered without configuring its port. The verdict is cached per connection
so multiplexed HTTP/2 frames stay attributed. TLS-wrapped traffic is encrypted
and is not sniffable.

- `container_http_requests_total`, `container_http_requests_duration_seconds_*`.
  These carry an extra `url` label holding the full request URL (the `Host`
  header joined with the request path, e.g. `example.com/api`; the path alone
  when no `Host` header is present). The query string is stripped, and label
  values are bounded per container by `PNET_MAX_URLS_PER_CONTAINER` (overflow
  becomes `~other`). URL extraction is best-effort cleartext HTTP/1.x only:
  HTTP/2 (h2c) requests and any `Host` header pushed past the 256-byte payload
  capture yield an empty `url`.
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

#### Resource utilization (`PNET_FEATURE_CONTAINER_RESOURCES=true`)

Per-container CPU, memory, block-I/O and PSI pressure read from the
cgroup v2 control files under `${PNET_SYSFS}/fs/cgroup/<cgroup-path>`
every `PNET_RESOURCES_INTERVAL`.

- CPU (`cpu.stat`): `container_resources_cpu_usage_seconds_total`,
  `container_resources_cpu_user_seconds_total`,
  `container_resources_cpu_system_seconds_total`,
  `container_resources_cpu_periods_total`,
  `container_resources_cpu_throttled_periods_total`,
  `container_resources_cpu_throttled_seconds_total`.
- Memory: `container_resources_memory_usage_bytes` (`memory.current`),
  `container_resources_memory_peak_bytes` (`memory.peak`, when present),
  `container_resources_memory_limit_bytes` (`memory.max`, omitted when
  unlimited).
- Block I/O (`io.stat`, summed across devices):
  `container_resources_io_read_bytes_total`,
  `container_resources_io_written_bytes_total`,
  `container_resources_io_reads_total`,
  `container_resources_io_writes_total`.
- PSI pressure (`cpu.pressure`, `memory.pressure`, `io.pressure`):
  `container_resources_cpu_pressure_seconds_total`,
  `container_resources_memory_pressure_seconds_total`,
  `container_resources_io_pressure_seconds_total`, each with a `level`
  label of `some` or `full` carrying the cumulative stall `total`.

### Node

When `PNET_FEATURE_NODE_METRICS=true` (default), the exporter also emits
host-level metrics scraped from `/proc`:

- `node_cpu_seconds_total{mode}`, `node_memory_*_bytes`, `node_uptime_seconds`.
- `node_disk_{reads,writes,read_bytes,written_bytes}_total{device}`.
- `node_network_{receive,transmit}_{bytes,errors}_total{interface}`.

### Build info

- `pnet_exporter_build_info` gauge: labels `version`, `commit`, `go_version`.

## Design choices

- Discovery is Podman-only (no docker/containerd/CRI-O integrations), but it
  covers every user on the host via a `/proc` cgroup scan rather than a single
  user's `podman ps`.
- L7 protocols are classified and parsed in Go from captured payloads; BPF
  only gathers bytes and socket tuples. HTTP is additionally autodiscovered by
  content sniffing on unregistered ports (HTTP/1.x and cleartext HTTP/2).
- The in-memory metric store uses flat maps keyed by label sets rather than
  a per-container subtree; this keeps the codebase small for Podman-sized
  deployments.

BPF programs live under [`bpf/`](bpf/) (TCP lifecycle, NAT, L7 payloads,
UDP/DNS, OOM); userspace dispatches ringbuf records in [`internal/ebpf`](internal/ebpf).
