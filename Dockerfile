# Stage 1: build the eBPF objects
FROM docker.io/library/debian:bookworm-slim AS bpf-builder

RUN apt-get update && apt-get install -y --no-install-recommends \
        clang \
        llvm \
        libbpf-dev \
        linux-headers-generic \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY bpf/ bpf/

RUN clang -O2 -g -target bpf -D__TARGET_ARCH_x86 \
        -I/usr/include/bpf \
        -c bpf/tcp_state.bpf.c     -o bpf/tcp_state.bpf.o && \
    clang -O2 -g -target bpf -D__TARGET_ARCH_x86 \
        -I/usr/include/bpf \
        -c bpf/tcp_retransmit.bpf.c -o bpf/tcp_retransmit.bpf.o && \
    clang -O2 -g -target bpf -D__TARGET_ARCH_x86 \
        -I/usr/include/bpf \
        -c bpf/tcp_bytes.bpf.c      -o bpf/tcp_bytes.bpf.o && \
    clang -O2 -g -target bpf -D__TARGET_ARCH_x86 \
        -I/usr/include/bpf \
        -c bpf/sys_connect.bpf.c    -o bpf/sys_connect.bpf.o && \
    clang -O2 -g -target bpf -D__TARGET_ARCH_x86 \
        -I/usr/include/bpf \
        -c bpf/protocols.bpf.c      -o bpf/protocols.bpf.o

# Stage 2: build the Go binary
FROM docker.io/library/golang:1.23-bookworm AS go-builder

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build \
        -ldflags="-s -w \
            -X pnet-exporter/internal/collector.version=$(git describe --tags --always --dirty 2>/dev/null || echo dev) \
            -X pnet-exporter/internal/collector.commit=$(git rev-parse --short HEAD 2>/dev/null || echo unknown)" \
        -o /out/pnet-exporter .

# Stage 3: minimal runtime image
FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=go-builder  /out/pnet-exporter /pnet-exporter
COPY --from=bpf-builder /src/bpf/*.bpf.o  /bpf/

# eBPF and network namespace operations require elevated privileges.
# Run with --privileged or the following capabilities:
#   CAP_BPF, CAP_PERFMON, CAP_NET_ADMIN, CAP_SYS_ADMIN
USER 0

EXPOSE 9108

ENV PNET_LISTEN_ADDRESS=:9108 \
    PNET_BPF_DIR=/bpf

ENTRYPOINT ["/pnet-exporter"]
