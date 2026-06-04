package ebpf

import (
	"sync"
	"time"
)

// urlFlowKey identifies an in-flight request flow for associating a parsed
// request URL (only available on the request) with the later response, where
// the metric is actually emitted. It mirrors the destination fields of
// protocol.RequestKey but omits the correlation token, which differs between
// the HTTP request and response payloads.
type urlFlowKey struct {
	containerID       string
	destination       string
	actualDestination string
}

type urlEntry struct {
	url  string
	seen time.Time
}

// requestURLs caches the URL parsed from an HTTP request until the matching
// response arrives on the same flow. Entries age out via ttl so abandoned
// requests (responses never seen) do not leak.
type requestURLs struct {
	mu      sync.Mutex
	ttl     time.Duration
	entries map[urlFlowKey]urlEntry
}

func newRequestURLs(ttl time.Duration) *requestURLs {
	if ttl <= 0 {
		ttl = 30 * time.Second
	}
	return &requestURLs{
		ttl:     ttl,
		entries: make(map[urlFlowKey]urlEntry),
	}
}

// Put records the URL parsed from a request for its flow.
func (c *requestURLs) Put(key urlFlowKey, url string) {
	if c == nil || url == "" {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries[key] = urlEntry{url: url, seen: time.Now()}
}

// Take returns and removes the cached URL for a flow.
func (c *requestURLs) Take(key urlFlowKey) (string, bool) {
	if c == nil {
		return "", false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	entry, ok := c.entries[key]
	if !ok {
		return "", false
	}
	delete(c.entries, key)
	return entry.url, true
}

// Prune drops entries not seen within the TTL.
func (c *requestURLs) Prune(now time.Time) {
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
