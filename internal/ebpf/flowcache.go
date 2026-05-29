package ebpf

import (
	"sync"
	"time"

	"pnet-exporter/internal/store"
)

// flowProtocols remembers the application protocol discovered for a socket
// flow by content sniffing, keyed by the socket 4-tuple. It lets multiplexed
// protocols like HTTP/2 - where only the first packet of a connection is
// self-identifying - attribute later events on the same connection. Entries
// age out via ttl so the table stays bounded by the set of active flows.
type flowProtocols struct {
	mu      sync.Mutex
	ttl     time.Duration
	entries map[SocketTuple]flowEntry
}

type flowEntry struct {
	proto store.Protocol
	seen  time.Time
}

// newFlowProtocols returns a flow cache with the given entry TTL.
func newFlowProtocols(ttl time.Duration) *flowProtocols {
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	return &flowProtocols{
		ttl:     ttl,
		entries: make(map[SocketTuple]flowEntry),
	}
}

// Get returns the cached protocol for a flow, refreshing its freshness so an
// actively used connection does not age out mid-stream.
func (c *flowProtocols) Get(tuple SocketTuple) (store.Protocol, bool) {
	if c == nil {
		return "", false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	entry, ok := c.entries[tuple]
	if !ok {
		return "", false
	}
	entry.seen = time.Now()
	c.entries[tuple] = entry
	return entry.proto, true
}

// Put records the protocol discovered for a flow.
func (c *flowProtocols) Put(tuple SocketTuple, proto store.Protocol) {
	if c == nil || proto == "" {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries[tuple] = flowEntry{proto: proto, seen: time.Now()}
}

// Prune drops entries not seen within the TTL.
func (c *flowProtocols) Prune(now time.Time) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for tuple, entry := range c.entries {
		if now.Sub(entry.seen) > c.ttl {
			delete(c.entries, tuple)
		}
	}
}
