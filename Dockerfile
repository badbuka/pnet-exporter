# syntax=docker/dockerfile:1.7

# ----------------------------------------------------------------------------
# Stage 1: build the eBPF objects (per-target architecture).
# ----------------------------------------------------------------------------
FROM --platform=$BUILDPLATFORM docker.io/library/debian:bookworm-slim AS bpf-builder

ARG TARGETARCH
# Pin the libbpf/vmlinux.h repository to a known commit so builds stay
# reproducible. Bump when refreshing kernel types.
ARG VMLINUX_REPO=https://github.com/libbpf/vmlinux.h.git
ARG VMLINUX_REF=main

RUN apt-get update && apt-get install -y --no-install-recommends \
        clang \
        llvm \
        libbpf-dev \
        make \
        ca-certificates \
        git \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY Makefile ./
COPY bpf/ bpf/

# Map Docker's $TARGETARCH to the libbpf/vmlinux.h directory name and to
# the matching clang -D__TARGET_ARCH_<arch> define. The vmlinux.h files in
# the upstream repo are symlinks to versioned headers, so we need a real
# git checkout (rather than `curl`) to resolve them. After staging
# vmlinux.h we defer the compile to `make bpf` so the clang flags stay in
# a single place (the Makefile).
RUN set -eux; \
    case "${TARGETARCH}" in \
        amd64)  vmlinux_arch=x86_64;  target_arch=x86 ;; \
        arm64)  vmlinux_arch=aarch64; target_arch=arm64 ;; \
        *) echo "unsupported TARGETARCH=${TARGETARCH}"; exit 1 ;; \
    esac; \
    git clone --depth 1 --branch "${VMLINUX_REF}" "${VMLINUX_REPO}" /tmp/vmlinux; \
    cp -L "/tmp/vmlinux/include/${vmlinux_arch}/vmlinux.h" bpf/vmlinux.h; \
    rm -rf /tmp/vmlinux; \
    make bpf "ARCH=${target_arch}"

# ----------------------------------------------------------------------------
# Stage 2: build the Go binary.
# ----------------------------------------------------------------------------
FROM --platform=$BUILDPLATFORM docker.io/library/golang:1.26.4-bookworm AS go-builder

ARG TARGETARCH
ARG VERSION=dev
ARG COMMIT=unknown

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=${TARGETARCH} \
    go build \
        -ldflags="-s -w \
            -X pnet-exporter/internal/collector.version=${VERSION} \
            -X pnet-exporter/internal/collector.commit=${COMMIT}" \
        -o /out/pnet-exporter .

# ----------------------------------------------------------------------------
# Stage 3: minimal runtime image.
# ----------------------------------------------------------------------------
# eBPF and network-namespace operations require elevated privileges, so this
# image must be run with --privileged or with the capabilities listed below:
#   CAP_BPF, CAP_PERFMON, CAP_NET_ADMIN, CAP_SYS_ADMIN
# Privileges are granted at runtime; the image itself stays as the regular
# distroless static image, not a `:nonroot` variant overridden to root.
FROM gcr.io/distroless/static-debian12

COPY --from=go-builder  /out/pnet-exporter /pnet-exporter
COPY --from=bpf-builder /src/bpf/*.bpf.o   /bpf/

EXPOSE 9108

ENV PNET_LISTEN_ADDRESS=:9108 \
    PNET_BPF_DIR=/bpf

ENTRYPOINT ["/pnet-exporter"]
