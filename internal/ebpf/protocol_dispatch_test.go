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

func TestProtocolCorrelationPostgres(t *testing.T) {
	payload := []byte{'Q', 0, 0, 0, 0}
	if got := protocolCorrelation(store.ProtocolPostgres, payload); got != "pg:query" {
		t.Fatalf("postgres correlation: %q", got)
	}
}

func TestProtocolCorrelationRedis(t *testing.T) {
	payload := []byte("GET key\r\n")
	if got := protocolCorrelation(store.ProtocolRedis, payload); got != "redis:GET" {
		t.Fatalf("redis correlation: %q", got)
	}
}

func TestProtocolCorrelationShortPayloads(t *testing.T) {
	tests := []struct {
		proto   store.Protocol
		payload []byte
	}{
		{store.ProtocolKafka, make([]byte, 4)},
		{store.ProtocolHTTP, []byte("NOT HTTP")},
		{store.ProtocolPostgres, nil},
		{store.ProtocolRedis, nil},
	}
	for _, tc := range tests {
		if got := protocolCorrelation(tc.proto, tc.payload); got != "" {
			t.Errorf("protocolCorrelation(%s, short): got %q, want empty", tc.proto, got)
		}
	}
}

func TestProtocolStatusPostgres(t *testing.T) {
	tests := []struct {
		payload []byte
		want    string
	}{
		{[]byte{'E'}, "error"},
		{[]byte{'C'}, "ok"},
		{[]byte{'X'}, "unknown"},
		{[]byte{}, "unknown"},
		{nil, "unknown"},
	}
	for _, tc := range tests {
		if got := protocolStatus(store.ProtocolPostgres, tc.payload); got != tc.want {
			t.Errorf("protocolStatus(postgres, %v) = %q; want %q", tc.payload, got, tc.want)
		}
	}
}

func TestProtocolStatusKafka(t *testing.T) {
	// Valid 12-byte header → "ok"
	validHeader := []byte{0, 0, 0, 8, 0, 0, 0, 1, 0, 0, 0, 42}
	if got := protocolStatus(store.ProtocolKafka, validHeader); got != "ok" {
		t.Fatalf("kafka valid header: got %q, want ok", got)
	}
	// Too short → "unknown"
	if got := protocolStatus(store.ProtocolKafka, make([]byte, 4)); got != "unknown" {
		t.Fatalf("kafka short: got %q, want unknown", got)
	}
}
