package protocol

import (
	"testing"
	"time"

	"pnet-exporter/internal/store"
)

func TestProtocolForPort(t *testing.T) {
	classifier := NewClassifier()
	protocol, ok := classifier.ProtocolForPort(5432)
	if !ok || protocol != store.ProtocolPostgres {
		t.Fatalf("expected postgres for 5432, got %q ok=%v", protocol, ok)
	}
}

func TestHTTPRequestParsing(t *testing.T) {
	request, ok := ParseHTTPRequest([]byte("GET /users HTTP/1.1\r\nHost: example\r\n\r\n"))
	if !ok || request.Method != "GET" || request.Path != "/users" {
		t.Fatalf("unexpected request: %#v ok=%v", request, ok)
	}

	status, ok := ParseHTTPStatus([]byte("HTTP/1.1 204 No Content\r\n\r\n"))
	if !ok || status != "204" {
		t.Fatalf("unexpected status: %q ok=%v", status, ok)
	}
}

func TestRedisParsing(t *testing.T) {
	command, ok := ParseRedisCommand([]byte("*2\r\n$3\r\nget\r\n$3\r\nkey\r\n"))
	if !ok || command != "GET" {
		t.Fatalf("unexpected redis command: %q ok=%v", command, ok)
	}
	if status := ParseRedisStatus([]byte("-ERR no\r\n")); status != "error" {
		t.Fatalf("unexpected redis status: %q", status)
	}
}

func TestKafkaHeaderParsing(t *testing.T) {
	header, ok := ParseKafkaRequestHeader([]byte{0, 0, 0, 8, 0, 0, 0, 1, 0, 0, 0, 42})
	if !ok || header.APIKey != 0 || header.APIVersion != 1 || header.CorrelationID != 42 {
		t.Fatalf("unexpected kafka header: %#v ok=%v", header, ok)
	}
}

func TestRequestTracker(t *testing.T) {
	tracker := NewRequestTracker(time.Second)
	key := RequestKey{ContainerID: "c1", Destination: "db:5432", Protocol: store.ProtocolPostgres, CorrelationID: "1"}
	start := time.Unix(10, 0)
	tracker.Start(key, start)
	duration, ok := tracker.Finish(key, start.Add(25*time.Millisecond))
	if !ok || duration != 25*time.Millisecond {
		t.Fatalf("unexpected duration: %s ok=%v", duration, ok)
	}
}
