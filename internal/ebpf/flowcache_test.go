package ebpf

import (
	"testing"
	"time"

	"pnet-exporter/internal/store"
)

func TestFlowProtocolsPutGet(t *testing.T) {
	c := newFlowProtocols(time.Minute)
	tuple := SocketTuple{SourcePort: 1234, DestinationPort: 8123, Family: familyIPv4}

	if _, ok := c.Get(tuple); ok {
		t.Fatal("expected miss on empty cache")
	}

	c.Put(tuple, store.ProtocolHTTP)
	got, ok := c.Get(tuple)
	if !ok || got != store.ProtocolHTTP {
		t.Fatalf("Get = %q, %v; want http, true", got, ok)
	}

	// A different flow must not collide.
	other := SocketTuple{SourcePort: 5678, DestinationPort: 9000, Family: familyIPv4}
	if _, ok := c.Get(other); ok {
		t.Fatal("expected miss for unrelated tuple")
	}
}

func TestFlowProtocolsPutEmptyIgnored(t *testing.T) {
	c := newFlowProtocols(time.Minute)
	tuple := SocketTuple{SourcePort: 1, DestinationPort: 2}
	c.Put(tuple, "")
	if _, ok := c.Get(tuple); ok {
		t.Fatal("empty protocol must not be cached")
	}
}

func TestFlowProtocolsPrune(t *testing.T) {
	c := newFlowProtocols(time.Minute)
	stale := SocketTuple{SourcePort: 1111, DestinationPort: 2222}
	fresh := SocketTuple{SourcePort: 3333, DestinationPort: 4444}

	c.Put(stale, store.ProtocolHTTP)
	c.Put(fresh, store.ProtocolHTTP)

	// Backdate the stale entry beyond the TTL.
	c.mu.Lock()
	e := c.entries[stale]
	e.seen = time.Now().Add(-2 * time.Minute)
	c.entries[stale] = e
	c.mu.Unlock()

	c.Prune(time.Now())

	if _, ok := c.Get(stale); ok {
		t.Fatal("stale entry should have been pruned")
	}
	if _, ok := c.Get(fresh); !ok {
		t.Fatal("fresh entry should survive pruning")
	}
}

func TestFlowProtocolsNilSafe(t *testing.T) {
	var c *flowProtocols
	if _, ok := c.Get(SocketTuple{}); ok {
		t.Fatal("nil cache Get must return false")
	}
	c.Put(SocketTuple{}, store.ProtocolHTTP) // must not panic
	c.Prune(time.Now())                      // must not panic
}
