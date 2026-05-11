package ebpf

import (
	"sync"
	"time"
)

// NATCache maps the post-DNAT destination ("actual destination") for a
// given original destination as observed by tcp_conntrack BPF events.
// Entries age out via ttl to keep the table bounded.
type NATCache struct {
	mu      sync.RWMutex
	entries map[string]natEntry
	ttl     time.Duration
}

type natEntry struct {
	actualDestination string
	updatedAt         time.Time
}

// NewNATCache returns a cache with the given entry TTL.
func NewNATCache(ttl time.Duration) *NATCache {
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	return &NATCache{
		entries: make(map[string]natEntry),
		ttl:     ttl,
	}
}

// Put records that connections originally destined for `original` are
// being NATed to `actual` (as seen by the kernel's conntrack table).
func (c *NATCache) Put(original, actual string) {
	if c == nil || original == "" || actual == "" || original == actual {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries[original] = natEntry{actualDestination: actual, updatedAt: time.Now()}
}

// Lookup returns the post-NAT destination for `original`. If no mapping
// exists, it returns `original` so callers can use it as a sensible
// default for label values.
func (c *NATCache) Lookup(original string) string {
	if c == nil || original == "" {
		return original
	}
	c.mu.RLock()
	entry, ok := c.entries[original]
	c.mu.RUnlock()
	if !ok {
		return original
	}
	return entry.actualDestination
}

// Prune drops entries that have not been refreshed within the TTL.
func (c *NATCache) Prune(now time.Time) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for key, entry := range c.entries {
		if now.Sub(entry.updatedAt) > c.ttl {
			delete(c.entries, key)
		}
	}
}
