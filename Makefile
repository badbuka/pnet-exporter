.PHONY: test test-integration lint ci bpf docker-build

IMAGE ?= pnet-exporter:latest

test:
	go test ./...

test-integration:
	go test -tags=integration ./test/integration/...

lint:
	golangci-lint run

ci: lint test

docker-build:
	docker build -t $(IMAGE) .

bpf:
	clang -O2 -g -target bpf -D__TARGET_ARCH_x86 -c bpf/tcp_state.bpf.c -o bpf/tcp_state.bpf.o
	clang -O2 -g -target bpf -D__TARGET_ARCH_x86 -c bpf/tcp_retransmit.bpf.c -o bpf/tcp_retransmit.bpf.o
	clang -O2 -g -target bpf -D__TARGET_ARCH_x86 -c bpf/tcp_bytes.bpf.c -o bpf/tcp_bytes.bpf.o
	clang -O2 -g -target bpf -D__TARGET_ARCH_x86 -c bpf/sys_connect.bpf.c -o bpf/sys_connect.bpf.o
	clang -O2 -g -target bpf -D__TARGET_ARCH_x86 -c bpf/protocols.bpf.c -o bpf/protocols.bpf.o
