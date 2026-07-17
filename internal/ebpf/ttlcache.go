package ebpf

import (
	"sync"
	"time"
)

// ttlCache is a mutex-guarded map whose entries expire after ttl without
// activity. It backs the loader's NAT, flow-protocol, and request-URL
// tables. Nil receivers are safe so partially constructed Loaders work.
type ttlCache[K comparable, V any] struct {
	mu      sync.Mutex
	ttl     time.Duration
	entries map[K]ttlEntry[V]
}

type ttlEntry[V any] struct {
	value V
	seen  time.Time
}

func newTTLCache[K comparable, V any](ttl time.Duration) *ttlCache[K, V] {
	return &ttlCache[K, V]{ttl: ttl, entries: make(map[K]ttlEntry[V])}
}

func (c *ttlCache[K, V]) put(key K, value V) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries[key] = ttlEntry[V]{value: value, seen: time.Now()}
}

// get returns the value without affecting freshness.
func (c *ttlCache[K, V]) get(key K) (V, bool) {
	if c == nil {
		var zero V
		return zero, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	entry, ok := c.entries[key]
	return entry.value, ok
}

// getRefresh returns the value and refreshes its freshness so an actively
// used entry does not age out.
func (c *ttlCache[K, V]) getRefresh(key K) (V, bool) {
	if c == nil {
		var zero V
		return zero, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	entry, ok := c.entries[key]
	if !ok {
		var zero V
		return zero, false
	}
	entry.seen = time.Now()
	c.entries[key] = entry
	return entry.value, true
}

// take returns and removes the value.
func (c *ttlCache[K, V]) take(key K) (V, bool) {
	if c == nil {
		var zero V
		return zero, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	entry, ok := c.entries[key]
	if !ok {
		var zero V
		return zero, false
	}
	delete(c.entries, key)
	return entry.value, true
}

// prune drops entries inactive for longer than the TTL.
func (c *ttlCache[K, V]) prune(now time.Time) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for key, entry := range c.entries {
		if now.Sub(entry.seen) > c.ttl {
			delete(c.entries, key)
		}
	}
}
