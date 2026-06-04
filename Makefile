.PHONY: test test-integration lint ci bpf vmlinux build docker-build clean

IMAGE  ?= pnet-exporter:latest
ARCH   ?= x86
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)

CLANG_FLAGS := -O2 -g -target bpf -D__TARGET_ARCH_$(ARCH) \
    -Wall -Werror=implicit-function-declaration \
    -I/usr/include/bpf -Ibpf

LDFLAGS := -s -w \
    -X pnet-exporter/internal/collector.version=$(VERSION) \
    -X pnet-exporter/internal/collector.commit=$(COMMIT)

BPF_OBJECTS := \
    bpf/tcp_state.bpf.o \
    bpf/tcp_retransmit.bpf.o \
    bpf/tcp_bytes.bpf.o \
    bpf/tcp_inbound.bpf.o \
    bpf/tcp_conntrack.bpf.o \
    bpf/l7.bpf.o \
    bpf/dns.bpf.o \
    bpf/oom.bpf.o

test:
	go test ./...

test-integration:
	go test -tags=integration ./test/integration/...

lint:
	golangci-lint run

ci: lint test

build:
	go build -ldflags='$(LDFLAGS)' -o pnet-exporter .

docker-build:
	docker build \
	  --build-arg VERSION=$(VERSION) \
	  --build-arg COMMIT=$(COMMIT) \
	  -t $(IMAGE) .

# vmlinux dumps kernel BTF into bpf/vmlinux.h. Requires bpftool and a kernel
# with /sys/kernel/btf/vmlinux. CI builds use the libbpf-bootstrap mirror.
vmlinux:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > bpf/vmlinux.h

bpf: bpf/vmlinux.h $(BPF_OBJECTS)

bpf/%.bpf.o: bpf/%.bpf.c bpf/common.h bpf/events.h bpf/vmlinux.h
	clang $(CLANG_FLAGS) -c $< -o $@

bpf/vmlinux.h:
	$(MAKE) vmlinux

clean:
	rm -f pnet-exporter bpf/*.bpf.o bpf/vmlinux.h
