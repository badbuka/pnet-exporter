# pnet-exporter

Prometheus exporter for Podman container network visibility with eBPF-based TCP, DNS, HTTP, Postgres, Redis, and Kafka metrics.

The project uses a flat Go layout with `main.go` in the repository root. eBPF C sources live in `bpf/`; Go runtime code lives in `internal/`.

## Configuration

Configuration is loaded from environment variables with the `PNET_` prefix.

Common variables:

- `PNET_LISTEN_ADDRESS`: Prometheus HTTP listen address, default `:9108`.
- `PNET_LOG_LEVEL`: `debug`, `info`, `warn`, or `error`, default `info`.
- `PNET_PODMAN_SOCKET`: Podman API socket path, default `/run/podman/podman.sock`.
- `PNET_PODMAN_BINARY`: Podman CLI fallback binary, default `podman`.
- `PNET_DISCOVERY_INTERVAL`: Podman discovery refresh interval, default `10s`.
- `PNET_FEATURE_NETWORK`, `PNET_FEATURE_DNS`, `PNET_FEATURE_HTTP`, `PNET_FEATURE_POSTGRES`, `PNET_FEATURE_REDIS`, `PNET_FEATURE_KAFKA`: feature toggles, default `true`.
- `PNET_FEATURE_LATENCY`: latency probing toggle, default `false`.
- `PNET_MAX_DESTINATIONS_PER_CONTAINER`, `PNET_MAX_FQDNS_PER_CONTAINER`, `PNET_MAX_PROTOCOL_KEYS_PER_CONTAINER`: cardinality limits.
- `PNET_DURATION_BUCKETS`, `PNET_DNS_DURATION_BUCKETS`: comma-separated Prometheus histogram buckets in seconds.
- `PNET_BPF_DIR`: directory containing compiled eBPF objects, default `./bpf`.

## Development

```sh
make test
make lint
make ci
```

Integration tests that require Podman are behind the `integration` build tag:

```sh
make test-integration
```

See `docs/metrics.md` for exported Prometheus series and standard histogram naming.

## Metrics

All metrics include `node_hostname`. Container-scoped metrics also include `container_id`, `container_name`, and `pod_id` labels. Destination and protocol label values are bounded by exporter configuration; overflow values are reported as `~other`.

## Network

- `container_net_tcp_listen_info` gauge: labels `listen_addr`, `proxy`.
- `container_net_tcp_successful_connects_total` counter: labels `destination`, `actual_destination`.
- `container_net_tcp_failed_connects_total` counter: label `destination`.
- `container_net_tcp_retransmits_total` counter: labels `destination`, `actual_destination`.
- `container_net_tcp_active_connections` gauge: labels `destination`, `actual_destination`.
- `container_net_tcp_bytes_sent_total` counter: labels `destination`, `actual_destination`.
- `container_net_tcp_bytes_received_total` counter: labels `destination`, `actual_destination`.
- `container_net_latency_seconds` gauge: label `destination_ip`.
- `ip_to_fqdn` gauge: labels `ip`, `fqdn`.

## DNS

- `container_dns_requests_total` counter: labels `domain`, `request_type`, `status`.
- `container_dns_requests_duration_seconds_bucket` counter: labels `le`.
- `container_dns_requests_duration_seconds_sum` counter.
- `container_dns_requests_duration_seconds_count` counter.

The originally requested DNS duration metric maps to the standard Prometheus histogram family above.

## HTTP

- `container_http_requests_total` counter: labels `destination`, `actual_destination`, `status`.
- `container_http_requests_duration_seconds_bucket` counter: labels `destination`, `actual_destination`, `le`.
- `container_http_requests_duration_seconds_sum` counter: labels `destination`, `actual_destination`.
- `container_http_requests_duration_seconds_count` counter: labels `destination`, `actual_destination`.

## Postgres

- `container_postgres_queries_total` counter: labels `destination`, `actual_destination`, `status`.
- `container_postgres_queries_duration_seconds_bucket` counter: labels `destination`, `actual_destination`, `le`.
- `container_postgres_queries_duration_seconds_sum` counter: labels `destination`, `actual_destination`.
- `container_postgres_queries_duration_seconds_count` counter: labels `destination`, `actual_destination`.

## Redis

- `container_redis_queries_total` counter: labels `destination`, `actual_destination`, `status`.
- `container_redis_queries_duration_seconds_bucket` counter: labels `destination`, `actual_destination`, `le`.
- `container_redis_queries_duration_seconds_sum` counter: labels `destination`, `actual_destination`.
- `container_redis_queries_duration_seconds_count` counter: labels `destination`, `actual_destination`.

## Kafka

- `container_kafka_requests_total` counter: labels `destination`, `actual_destination`, `status`.
- `container_kafka_requests_duration_seconds_bucket` counter: labels `destination`, `actual_destination`, `le`.
- `container_kafka_requests_duration_seconds_sum` counter: labels `destination`, `actual_destination`.
- `container_kafka_requests_duration_seconds_count` counter: labels `destination`, `actual_destination`.
