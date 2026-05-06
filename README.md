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
