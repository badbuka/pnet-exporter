package ebpf

import (
	"testing"

	"pnet-exporter/internal/store"
)

func TestProtocolCorrelationKafka(t *testing.T) {
	// size=8, api_key=0, api_version=0, correlation_id=42
	payload := []byte{0, 0, 0, 8, 0, 0, 0, 0, 0, 0, 0, 42}
	got := protocolCorrelation(store.ProtocolKafka, DirRequest, payload)
	if got != "kafka:42" {
		t.Fatalf("unexpected correlation: %q", got)
	}
}

// TestProtocolCorrelationKafkaRequestResponseMatch guards the core Kafka
// correlation contract: a request and its echoed response must yield the same
// token despite their different header layouts (request carries
// api_key/api_version before correlation_id; response carries it right after
// the size prefix).
func TestProtocolCorrelationKafkaRequestResponseMatch(t *testing.T) {
	// Request: size, api_key=1 (fetch), api_version=11, correlation_id=42
	request := []byte{0, 0, 0, 16, 0, 1, 0, 11, 0, 0, 0, 42}
	// Response: size, correlation_id=42, then body bytes.
	response := []byte{0, 0, 0, 16, 0, 0, 0, 42, 0, 0, 0, 0}

	reqToken := protocolCorrelation(store.ProtocolKafka, DirRequest, request)
	respToken := protocolCorrelation(store.ProtocolKafka, DirResponse, response)
	if reqToken != "kafka:42" {
		t.Fatalf("request token: got %q, want kafka:42", reqToken)
	}
	if respToken != reqToken {
		t.Fatalf("response token %q does not match request token %q", respToken, reqToken)
	}
}

// Non-Kafka protocols have no direction-stable token: responses echo
// nothing from the request, so both directions must fall back to the
// destination (the caller substitutes dst on empty).
func TestProtocolCorrelationNonKafkaFallsBack(t *testing.T) {
	for _, tc := range []struct {
		proto   store.Protocol
		payload []byte
	}{
		{store.ProtocolHTTP, []byte("GET /api HTTP/1.1\r\nHost: example\r\n\r\n")},
		{store.ProtocolPostgres, []byte{'Q', 0, 0, 0, 0}},
		{store.ProtocolRedis, []byte("GET key\r\n")},
	} {
		if got := protocolCorrelation(tc.proto, DirRequest, tc.payload); got != "" {
			t.Errorf("protocolCorrelation(%s, request): got %q, want empty (dst fallback)", tc.proto, got)
		}
		if got := protocolCorrelation(tc.proto, DirResponse, tc.payload); got != "" {
			t.Errorf("protocolCorrelation(%s, response): got %q, want empty (dst fallback)", tc.proto, got)
		}
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
		if got := protocolCorrelation(tc.proto, DirRequest, tc.payload); got != "" {
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
