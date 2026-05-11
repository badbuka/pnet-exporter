package ebpf

import (
	"testing"

	"pnet-exporter/internal/store"
)

func TestProtocolCorrelationKafka(t *testing.T) {
	payload := []byte{0, 0, 0, 8, 0, 0, 0, 1, 0, 0, 0, 42}
	got := protocolCorrelation(store.ProtocolKafka, payload)
	if got != "kafka:42" {
		t.Fatalf("unexpected correlation: %q", got)
	}
}

func TestProtocolCorrelationHTTP(t *testing.T) {
	payload := []byte("GET /api HTTP/1.1\r\nHost: example\r\n\r\n")
	got := protocolCorrelation(store.ProtocolHTTP, payload)
	if got != "http:GET /api" {
		t.Fatalf("unexpected correlation: %q", got)
	}
}

func TestProtocolStatusHTTP(t *testing.T) {
	payload := []byte("HTTP/1.1 200 OK\r\n\r\n")
	if got := protocolStatus(store.ProtocolHTTP, payload); got != "200" {
		t.Fatalf("status: %q", got)
	}
}

func TestProtocolStatusRedis(t *testing.T) {
	if got := protocolStatus(store.ProtocolRedis, []byte("-ERR something\r\n")); got != "error" {
		t.Fatalf("status: %q", got)
	}
	if got := protocolStatus(store.ProtocolRedis, []byte("+OK\r\n")); got != "ok" {
		t.Fatalf("status: %q", got)
	}
}
