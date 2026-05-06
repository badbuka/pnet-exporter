.PHONY: test test-integration lint ci bpf vmlinux build docker-build clean

IMAGE  ?= pnet-exporter:latest
ARCH   ?= x86
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)

CLANG_FLAGS := -O2 -g -target bpf -D__TARGET_ARCH_$(ARCH) -I/usr/include/bpf -Ibpf

LDFLAGS := -s -w \
    -X pnet-exporter/internal/collector.version=$(VERSION) \
    -X pnet-exporter/internal/collector.commit=$(COMMIT)

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

bpf: bpf/vmlinux.h
	clang $(CLANG_FLAGS) -c bpf/tcp_state.bpf.c      -o bpf/tcp_state.bpf.o
	clang $(CLANG_FLAGS) -c bpf/tcp_retransmit.bpf.c -o bpf/tcp_retransmit.bpf.o

bpf/vmlinux.h:
	$(MAKE) vmlinux

clean:
	rm -f pnet-exporter bpf/*.bpf.o bpf/vmlinux.h
