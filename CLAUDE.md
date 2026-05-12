# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```sh
make test                # Go unit tests
make test-integration    # integration tests (require Podman, behind `integration` build tag)
make lint                # golangci-lint
make ci                  # lint + test
make build               # compile binary with version/commit stamped via ldflags
make bpf                 # compile eBPF C objects (requires clang + bpftool)
make docker-build        # multi-arch container image
make clean               # remove binary and compiled BPF objects
```

Run a single Go test:
```sh
go test ./internal/store/... -run TestSomething
```

BPF objects must be pre-compiled before the binary can load them at runtime. In CI and Docker builds this is handled automatically; locally you need `clang`, `bpftool`, and kernel BTF (`/sys/kernel/btf/vmlinux`).

## Architecture

```
podman ps → identity.Cache (PID/cgroup index)
                 ↕
         ebpf.Loader (cilium/ebpf)
           loads BPF objects from PNET_BPF_DIR
           attaches kprobes/tracepoints
           reads single shared ringbuf
                 ↓ typed events (kind byte)
         dispatch + NAT cache (internal/ebpf)
           → store.Store (in-memory Prometheus snapshots)
                 ↑ also written by:
           prober   (ICMP RTT via setns)
           delays   (CPU/IO from /proc schedstat)
           node     (/proc cpu/mem/disk/net)
                 ↓
         collector.* → prometheus.Registry → /metrics
```

**Key packages:**

- `internal/config` — all runtime config via `PNET_*` env vars using `envconfig`; feature flags control which subsystems start.
- `internal/identity` — maps container PIDs/cgroups → container labels; periodically refreshed from Podman.
- `internal/ebpf` — loads and attaches BPF programs, reads ring buffer, dispatches events, maintains NAT cache. `protocol_dispatch.go` correlates L7 request/response pairs.
- `internal/store` — flat in-memory maps keyed by label sets; no per-container subtree. A janitor goroutine prunes expired series.
- `internal/protocol` — pure-Go parsers (HTTP, DNS, Postgres, Redis, Kafka); BPF only captures raw bytes.
- `internal/collector` — thin Prometheus `Collector` wrappers over `store.Store`.
- `internal/prober` — ICMP RTT probing inside each container's network namespace via `setns`.
- `internal/delays` — reads `/proc/<pid>/schedstat` and `/proc/<pid>/stat` for CPU/IO delay counters.
- `internal/node` — host-level `/proc` collectors (CPU, memory, disk, network).
- `bpf/` — C sources; each file produces one `.bpf.o`. All programs share the `events` ring buffer. `events.h` defines the shared event structs; `common.h` has helpers.

**Adding a new BPF program:**

1. Add `bpf/<name>.bpf.c` with a `SEC(...)` annotation and push events through `events`.
2. Add the object to `BPF_OBJECTS` in `Makefile`.
3. Add a `programDescriptor` entry in `internal/ebpf/protocol_dispatch.go` (or `loader.go`).
4. Add a new event `kind` in `bpf/events.h` and a matching Go struct in `internal/ebpf/events.go`.
5. Add a dispatch case in `internal/ebpf/loader.go`.

## Linting

`.golangci.yml` runs `errcheck`, `errorlint`, `govet`, `staticcheck`, `unused`, `bodyclose`, `ineffassign`, `misspell`. The `bpf/` directory is excluded. Timeout is 5 minutes.

## Configuration

All env vars use the `PNET_` prefix. Feature flags (`PNET_FEATURE_*`) gate entire subsystems; when `false` the goroutine/loader for that subsystem is never started. See README.md for the full variable reference.

## Platform notes

eBPF programs only attach on Linux. `internal/ebpf/loader_linux.go` contains the real implementation; `loader_other.go` is a no-op stub for non-Linux builds. Integration tests require a Podman socket and are gated behind the `integration` build tag.
