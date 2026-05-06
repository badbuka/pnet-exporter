# pnet-exporter

Prometheus exporter for Podman container network visibility, backed by eBPF.

The repository uses a flat Go layout: `main.go` at the root, runtime code under
`internal/`, eBPF C sources under `bpf/`. The current build ships TCP
connect-state and retransmit observability; HTTP/DNS/Postgres/Redis/Kafka
classifiers exist as Go-side parsers but are not yet wired to BPF programs.

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
- `PNET_FEATURE_NETWORK`, `PNET_FEATURE_DNS`, `PNET_FEATURE_HTTP`,
  `PNET_FEATURE_POSTGRES`, `PNET_FEATURE_REDIS`, `PNET_FEATURE_KAFKA`: feature
  toggles, default `true`.
- `PNET_FEATURE_LATENCY`: latency probing toggle, default `false`.
- `PNET_MAX_DESTINATIONS_PER_CONTAINER`, `PNET_MAX_FQDNS_PER_CONTAINER`:
  cardinality limits.
- `PNET_METRIC_TTL`: TTL for *momentary* series (active connections, latency,
  histograms, IP→FQDN); counter series are pruned only when their container
  disappears, to preserve counter monotonicity.
- `PNET_CLEANUP_INTERVAL`: how often the janitor runs.
- `PNET_DURATION_BUCKETS`, `PNET_DNS_DURATION_BUCKETS`: comma-separated
  Prometheus histogram buckets in seconds.
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

## Metrics

All metrics include the `node_hostname` label. Container-scoped metrics
additionally include `container_id`, `container_name`, and `pod_id`.
Destination label values are bounded per container by
`PNET_MAX_DESTINATIONS_PER_CONTAINER`; overflow values become `~other`.

### TCP (active)

- `container_net_tcp_listen_info` gauge: labels `listen_addr`, `proxy`.
- `container_net_tcp_successful_connects_total` counter: labels `destination`,
  `actual_destination`.
- `container_net_tcp_failed_connects_total` counter: label `destination`.
- `container_net_tcp_retransmits_total` counter: labels `destination`,
  `actual_destination`.
- `container_net_tcp_active_connections` gauge: labels `destination`,
  `actual_destination`.
- `container_net_tcp_bytes_sent_total` counter: labels `destination`,
  `actual_destination`.
- `container_net_tcp_bytes_received_total` counter: labels `destination`,
  `actual_destination`.
- `container_net_latency_seconds` gauge: label `destination_ip`.
- `ip_to_fqdn` gauge: labels `ip`, `fqdn`.

### Reserved (not yet emitted by BPF programs)

The metric names below are exposed by the collectors and the parsers in
`internal/protocol/` are wired up, but no BPF program currently feeds them.
They will appear with zero series until classifiers ship.

- `container_dns_requests_total`,
  `container_dns_requests_duration_seconds_{bucket,sum,count}`.
- `container_http_requests_total`,
  `container_http_requests_duration_seconds_{bucket,sum,count}`.
- `container_postgres_queries_total`,
  `container_postgres_queries_duration_seconds_{bucket,sum,count}`.
- `container_redis_queries_total`,
  `container_redis_queries_duration_seconds_{bucket,sum,count}`.
- `container_kafka_requests_total`,
  `container_kafka_requests_duration_seconds_{bucket,sum,count}`.

### Build info

- `pnet_exporter_build_info` gauge: labels `version`, `commit`, `go_version`.
