# syntax=docker/dockerfile:1.7

# ----------------------------------------------------------------------------
# Stage 1: build the eBPF objects (per-target architecture).
# ----------------------------------------------------------------------------
FROM --platform=$BUILDPLATFORM docker.io/library/debian:bookworm-slim AS bpf-builder

ARG TARGETARCH
ARG LIBBPF_BOOTSTRAP_REF=23d3334cebf3da72c5dab7d5e49aac598e5e9b1b

RUN apt-get update && apt-get install -y --no-install-recommends \
        clang \
        llvm \
        libbpf-dev \
        linux-headers-generic \
        ca-certificates \
        curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY bpf/ bpf/

# Map Docker's $TARGETARCH to libbpf-bootstrap's vmlinux directory layout
# and the matching clang -D__TARGET_ARCH_<arch> define.
RUN set -eux; \
    case "${TARGETARCH}" in \
        amd64)  vmlinux_arch=x86;   target_arch=x86 ;; \
        arm64)  vmlinux_arch=arm64; target_arch=arm64 ;; \
        *) echo "unsupported TARGETARCH=${TARGETARCH}"; exit 1 ;; \
    esac; \
    curl -fsSL \
        "https://raw.githubusercontent.com/libbpf/libbpf-bootstrap/${LIBBPF_BOOTSTRAP_REF}/vmlinux/${vmlinux_arch}/vmlinux.h" \
        -o bpf/vmlinux.h; \
    for src in bpf/*.bpf.c; do \
        clang -O2 -g -target bpf "-D__TARGET_ARCH_${target_arch}" \
            -I/usr/include/bpf -Ibpf \
            -c "${src}" -o "${src%.c}.o"; \
    done

# ----------------------------------------------------------------------------
# Stage 2: build the Go binary.
# ----------------------------------------------------------------------------
FROM --platform=$BUILDPLATFORM docker.io/library/golang:1.26.2-bookworm AS go-builder

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
