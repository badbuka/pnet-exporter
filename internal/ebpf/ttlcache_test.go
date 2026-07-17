package ebpf

import (
	"testing"
	"time"

	"pnet-exporter/internal/store"
)

func TestTTLCachePutGet(t *testing.T) {
	c := newTTLCache[SocketTuple, store.Protocol](time.Minute)
	tuple := SocketTuple{SourcePort: 1234, DestinationPort: 8123, Family: familyIPv4}

	if _, ok := c.get(tuple); ok {
		t.Fatal("expected miss on empty cache")
	}
	c.put(tuple, store.ProtocolHTTP)
	if got, ok := c.get(tuple); !ok || got != store.ProtocolHTTP {
		t.Fatalf("get = %q, %v; want http, true", got, ok)
	}
	other := SocketTuple{SourcePort: 5678, DestinationPort: 9000, Family: familyIPv4}
	if _, ok := c.get(other); ok {
		t.Fatal("expected miss for unrelated tuple")
	}
}

func TestTTLCacheGetRefreshExtendsLife(t *testing.T) {
	c := newTTLCache[string, string](time.Minute)
	c.put("stale", "a")
	c.put("hot", "b")

	// Backdate both beyond the TTL, then refresh only "hot".
	past := time.Now().Add(-2 * time.Minute)
	c.entries["stale"] = ttlEntry[string]{value: "a", seen: past}
	c.entries["hot"] = ttlEntry[string]{value: "b", seen: past}
	if _, ok := c.getRefresh("hot"); !ok {
		t.Fatal("getRefresh must hit")
	}

	c.prune(time.Now())
	if _, ok := c.get("stale"); ok {
		t.Fatal("stale entry should have been pruned")
	}
	if _, ok := c.get("hot"); !ok {
		t.Fatal("refreshed entry should survive pruning")
	}
}

func TestTTLCacheTakeRemoves(t *testing.T) {
	c := newTTLCache[string, string](time.Minute)
	c.put("k", "v")
	if got, ok := c.take("k"); !ok || got != "v" {
		t.Fatalf("take = %q, %v; want v, true", got, ok)
	}
	if _, ok := c.take("k"); ok {
		t.Fatal("second take must miss")
	}
}

func TestTTLCacheNilSafe(t *testing.T) {
	var c *ttlCache[string, string]
	if _, ok := c.get("k"); ok {
		t.Fatal("nil get must miss")
	}
	if _, ok := c.getRefresh("k"); ok {
		t.Fatal("nil getRefresh must miss")
	}
	if _, ok := c.take("k"); ok {
		t.Fatal("nil take must miss")
	}
	c.put("k", "v")      // must not panic
	c.prune(time.Now())  // must not panic
}

func TestActualDestinationFallback(t *testing.T) {
	l := &Loader{nat: newTTLCache[string, string](time.Minute)}
	if got := l.actualDestination("svc:80"); got != "svc:80" {
		t.Fatalf("unmapped dst must pass through, got %q", got)
	}
	l.nat.put("svc:80", "10.0.0.5:80")
	if got := l.actualDestination("svc:80"); got != "10.0.0.5:80" {
		t.Fatalf("mapped dst: got %q", got)
	}
}
