package protocol

import (
	"testing"
	"time"

	"pnet-exporter/internal/store"
)

func TestProtocolForPort(t *testing.T) {
	classifier, err := NewClassifier(nil)
	if err != nil {
		t.Fatalf("NewClassifier(nil) error: %v", err)
	}
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

func TestNormalizeStatus(t *testing.T) {
	tests := []struct {
		protocol store.Protocol
		raw      string
		want     string
	}{
		{store.ProtocolHTTP, "200", "200"},
		{store.ProtocolHTTP, "404", "404"},
		{store.ProtocolHTTP, "", "unknown"},
		{store.ProtocolPostgres, "ok", "ok"},
		{store.ProtocolPostgres, "error", "error"},
		{store.ProtocolPostgres, "timeout", "timeout"},
		{store.ProtocolPostgres, "junk", "unknown"},
		{store.ProtocolRedis, "ok", "ok"},
		{store.ProtocolRedis, "error", "error"},
		{store.ProtocolKafka, "ok", "ok"},
		{store.ProtocolKafka, "junk", "unknown"},
		{"unknown", "anything", "unknown"},
		{"unknown", "", "unknown"},
	}
	for _, tc := range tests {
		got := NormalizeStatus(tc.protocol, tc.raw)
		if got != tc.want {
			t.Errorf("NormalizeStatus(%q, %q) = %q; want %q", tc.protocol, tc.raw, got, tc.want)
		}
	}
}

func TestProtocolForPortUnknown(t *testing.T) {
	c, err := NewClassifier(nil)
	if err != nil {
		t.Fatalf("NewClassifier(nil) error: %v", err)
	}
	if _, ok := c.ProtocolForPort(1234); ok {
		t.Fatal("expected false for unknown port 1234")
	}
}

func TestClassifierExtraPorts(t *testing.T) {
	c, err := NewClassifier(map[store.Protocol][]uint16{
		store.ProtocolPostgres: {15432, 25432},
		store.ProtocolRedis:    {16379},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if proto, ok := c.ProtocolForPort(15432); !ok || proto != store.ProtocolPostgres {
		t.Fatalf("expected postgres for 15432, got %q ok=%v", proto, ok)
	}
	if proto, ok := c.ProtocolForPort(25432); !ok || proto != store.ProtocolPostgres {
		t.Fatalf("expected postgres for 25432, got %q ok=%v", proto, ok)
	}
	if proto, ok := c.ProtocolForPort(16379); !ok || proto != store.ProtocolRedis {
		t.Fatalf("expected redis for 16379, got %q ok=%v", proto, ok)
	}
	if proto, ok := c.ProtocolForPort(5432); !ok || proto != store.ProtocolPostgres {
		t.Fatalf("default 5432 lost: %q ok=%v", proto, ok)
	}
}

func TestClassifierExtraPortConflictWithDefault(t *testing.T) {
	_, err := NewClassifier(map[store.Protocol][]uint16{
		store.ProtocolHTTP: {5432},
	})
	if err == nil {
		t.Fatal("expected conflict when extra HTTP port collides with default postgres 5432")
	}
}

func TestClassifierExtraPortConflictAcrossExtras(t *testing.T) {
	_, err := NewClassifier(map[store.Protocol][]uint16{
		store.ProtocolHTTP:  {17000},
		store.ProtocolRedis: {17000},
	})
	if err == nil {
		t.Fatal("expected conflict when two extra protocols share the same port")
	}
}

func TestClassifierSameProtocolDuplicateExtraOK(t *testing.T) {
	if _, err := NewClassifier(map[store.Protocol][]uint16{
		store.ProtocolPostgres: {5432, 5432},
	}); err != nil {
		t.Fatalf("same-protocol duplicate should not error, got %v", err)
	}
}

func TestRequestTrackerMiss(t *testing.T) {
	tracker := NewRequestTracker(time.Second)
	key := RequestKey{ContainerID: "c1", Destination: "db:5432", Protocol: store.ProtocolPostgres, CorrelationID: "never-started"}
	if _, ok := tracker.Finish(key, time.Now()); ok {
		t.Fatal("expected miss on key that was never started")
	}
}

func TestRequestTrackerPrune(t *testing.T) {
	tracker := NewRequestTracker(time.Second)
	key := RequestKey{ContainerID: "c1", Destination: "db:5432", Protocol: store.ProtocolPostgres, CorrelationID: "p1"}
	start := time.Unix(10, 0)
	tracker.Start(key, start)
	tracker.Prune(start.Add(2 * time.Second))
	if _, ok := tracker.Finish(key, start.Add(3*time.Second)); ok {
		t.Fatal("expected miss after TTL prune")
	}
}
