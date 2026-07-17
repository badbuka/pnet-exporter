# Repository Guidelines

## Project Overview

pnet-exporter is a Prometheus exporter for per-container (Podman/Docker) network visibility, built on eBPF. It captures TCP connect/close/bytes/retransmits, inbound (server-side) TCP, DNS requests + latency, L7 protocol stats (HTTP/Postgres/Redis/Kafka), OOM kills, ICMP RTT probing, delay accounting, and cgroup v2 resource/PSI metrics — all labeled with container identity. MIT license. Go 1.26, module `pnet-exporter`.

## Architecture & Data Flow

```
bpf/*.bpf.c (kprobes/tracepoints) ──> shared "events" ringbuf ──> internal/ebpf Loader.consume
    ──> PeekKind → Decode*Event → dispatchTCP/NAT/L7/DNS/OOM
    ──> resolveContainer (cgroup id → identity.Cache, PID fallback)
    ──> NATCache / flow sniffing / protocol.Classifier / RequestTracker
    ──> store.Store (single RWMutex, cardinality-bounded maps)
    ──> collector.* call store.Snapshot() per scrape ──> :9108/metrics
```

- Entry point `main.go` wires everything manually (no DI framework, concrete structs, no single-impl interfaces): `config.Load` → kernel checks → `identity.Cache` + `discovery.Discoverer` + `store.Store` → `protocol.Classifier` → `ebpf.Loader.Start` → feature-gated goroutines (prober, delays, resources, discovery loop, store janitor) → HTTP `:9108` (`/metrics`, `/healthz`) → signal-based shutdown.
- **No bpf2go / no go:embed.** `.bpf.o` objects are precompiled with clang (`make bpf`) and loaded at runtime from `PNET_BPF_DIR` (default `./bpf`) via cilium/ebpf `LoadCollectionSpec`. One shared ringbuf map is created from the first spec and injected into all collections via `MapReplacements`.
- Attach table lives in `internal/ebpf/loader.go` (`programs []programDescriptor`). Missing `.o` files or failed attaches are Warn-and-skip (partial startup OK).
- Side paths poll on tickers and write into the same store: `prober` (ICMP via setns), `delays` (schedstat), `resources` (cgroup v2). `node` reads /proc at scrape time instead.
- Container attribution: `bpf_get_current_cgroup_id()` in BPF matched against `identity.Cache` (discovery stats `/sys/fs/cgroup` inodes; /proc cgroup scan is source of truth, Podman/Docker sockets only enrich names).

**Sync points that MUST hold when editing:**
- `bpf/events.h` `PNET_EVENT_*` (1–17) ↔ Go `EventKind` consts in `internal/ebpf/events.go`
- Struct layouts in `bpf/common.h` ↔ hand-written `binary.LittleEndian` decoders in `internal/ebpf/events.go` (offset comments mirror the C structs)

## Key Directories

| Path | Purpose |
|---|---|
| `main.go` | Entry point; all wiring in `run()` |
| `internal/config` | `PNET_*` env config (envconfig, flat struct, `default:` tags + `Validate()`) |
| `internal/ebpf` | BPF object loading, attach, ringbuf consume, event decode/dispatch, NAT/flow/URL caches |
| `internal/store` | In-memory metric store; event DTOs in `types.go`, map keys in `keys.go`, `Snapshot()` for collectors |
| `internal/collector` | prometheus.Collector impls (network, protocol, runtime, resources, build) |
| `internal/discovery` | /proc cgroup scan + Podman/Docker socket enrichment |
| `internal/identity` | Container cache indexed by ID/PID/cgroup |
| `internal/protocol` | Port classifier + wire parsers (HTTP/1+h2 HPACK, DNS, Postgres, Redis, Kafka), RequestTracker |
| `internal/prober` | ICMP RTT probing from container netns (setns, `runtime.LockOSThread`) |
| `internal/delays`, `internal/resources`, `internal/node` | /proc & cgroup v2 pollers/parsers |
| `bpf/` | BPF C sources + `common.h` (structs, ringbuf), `events.h` (event kinds) |
| `test/integration` | Integration tests behind `//go:build integration` |
| `grafana/` | Importable dashboard (`pnet-exporter.json`) |
| `packaging/`, `nfpm.yaml` | systemd unit + deb/rpm packaging |

## Development Commands

```sh
make build             # go build with -ldflags version/commit injection → ./pnet-exporter
make bpf               # clang-compile bpf/*.bpf.c → .bpf.o (needs clang, bpftool, bpf/vmlinux.h)
make vmlinux           # regenerate bpf/vmlinux.h from /sys/kernel/btf/vmlinux
make test              # go test ./...
make test-integration  # go test -tags=integration ./test/integration/...
make lint              # golangci-lint run (v2 config)
make ci                # lint + test
make docker-build      # multi-stage image (compiles BPF inside Docker)
```

Run locally: `make bpf build && sudo ./pnet-exporter` (Linux only). CI runs `go vet ./...` and `go test -race -count=1 ./...`.

## Code Conventions & Common Patterns

- **Logging:** `log/slog` TextHandler; logger injected via constructors.
- **Errors:** `fmt.Errorf("context: %w")` wrapping, `errors.New` for static; per-event/tick failures are logged Debug/Warn and skipped — only config errors, required kernel checks, and classifier port conflicts are fatal.
- **Concurrency:** `signal.NotifyContext` root ctx; goroutines are `for { select { <-ctx.Done(): return; <-ticker.C: ... } }` ticker loops; mutex-guarded maps (single `sync.RWMutex` in store), atomics for stats.
- **Platform split:** `//go:build linux` real impl + `//go:build !linux` no-op stub file pairs (`loader_linux.go`/`loader_other.go`, `ping_linux.go`/`ping_other.go`) — project must stay buildable on macOS/Windows.
- **Naming:** `New*` constructors; store verbs `Observe*/Inc*/Dec*/Add*/Set*/Record*`; metric names `container_*` / `node_*` / `pnet_exporter_build_info`; env prefix `PNET_`.
- **Testability:** constructors accept filesystem roots (`procFS`, `sysFS`) so tests use `t.TempDir()` fixtures; ebpf caches use nil-receiver-safe methods.
- **Cardinality guards:** store bounds label values (`~other` overflow, `dyn_ports` collapse); keep this discipline when adding series.
- Config is env-only (no CLI flags); validation errors reference the `PNET_*` var name.

## Important Files

- `main.go` — entry, wiring, HTTP server
- `internal/ebpf/loader.go` — canonical BPF attach table + dispatch
- `internal/ebpf/events.go` + `bpf/events.h` + `bpf/common.h` — wire format contract (edit together)
- `internal/config/config.go` — every `PNET_*` setting + defaults
- `internal/store/store.go` — all series state, cardinality guards, pruning
- `Makefile` — build/test/lint/bpf targets, ldflags version injection
- `Dockerfile` — 3-stage: clang BPF build → Go build → distroless runtime
- `.golangci.yml` — linters: bodyclose, errcheck, errorlint, govet, ineffassign, misspell, staticcheck, unused (bpf/ excluded)
- `.github/workflows/ci.yml` — vet + race tests + golangci-lint + Snyk; `release.yml` — multi-arch Docker + nfpm deb/rpm
- `grafana/pnet-exporter.json` — dashboard; update when renaming/adding metrics

## Runtime/Tooling Preferences

- **Linux-only at runtime**, kernel 5.8+ (`CONFIG_BPF_SYSCALL`; `CONFIG_SCHEDSTATS` for delay accounting), cgroup v2. Needs root or `CAP_BPF, CAP_PERFMON, CAP_NET_ADMIN, CAP_SYS_ADMIN` (containers run `--privileged --pid=host --network=host`).
- Go 1.26.5; deps: cilium/ebpf, prometheus/client_golang, kelseyhightower/envconfig, golang.org/x/sys. Not vendored. **Do not add test frameworks** (no testify/ginkgo) or bpf2go.
- BPF toolchain: clang + `bpftool` + kernel BTF; Docker builds fetch `vmlinux.h` from the libbpf/vmlinux.h repo per arch.
- Package manager: Go modules; releases via nfpm (deb/rpm) and Docker Hub `badbuka/pnet-exporter`.

## Testing & QA

- Stdlib `testing` only, table-driven, colocated `*_test.go` per package (22 files). No root needed anywhere: eBPF code is tested userspace-side (decoders + `Loader.dispatch*` via `newTestLoader`, which loads no BPF objects).
- Patterns: hand-crafted byte buffers for parsers/decoders; `t.TempDir()` as fake procfs/sysfs roots; `t.Setenv` for config; Prometheus assertions via `prometheus.NewRegistry().Gather()`.
- Integration tier: `test/integration/` behind `//go:build integration` (synthetic procfs through `Discoverer.List`; CI does not run it — run manually before touching discovery).
- No coverage gate. Lint clean (`make lint`) + `go vet` + `-race` is the CI bar.
