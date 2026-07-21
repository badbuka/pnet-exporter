package protocol

import (
	"sync"
	"time"

	"pnet-exporter/internal/store"
)

// RequestKey uniquely identifies an in-flight protocol request for matching it to its response.
type RequestKey struct {
	ContainerID       string
	Destination       string
	ActualDestination string
	CorrelationID     string
	Protocol          store.Protocol
}

// RequestTracker maintains in-flight protocol request start times keyed by RequestKey. It is safe for concurrent use.
type RequestTracker struct {
	mu       sync.Mutex
	requests map[RequestKey]time.Time
	ttl      time.Duration
}

func NewRequestTracker(ttl time.Duration) *RequestTracker {
	return &RequestTracker{requests: make(map[RequestKey]time.Time), ttl: ttl}
}

func (t *RequestTracker) Start(key RequestKey, now time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.requests[key] = now
}

func (t *RequestTracker) Finish(key RequestKey, now time.Time) (time.Duration, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()

	startedAt, ok := t.requests[key]
	if !ok {
		return 0, false
	}
	delete(t.requests, key)
	return now.Sub(startedAt), true
}

func (t *RequestTracker) Prune(now time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()

	for key, startedAt := range t.requests {
		if now.Sub(startedAt) > t.ttl {
			delete(t.requests, key)
		}
	}
}

// Len reports the number of in-flight requests; intended for tests and
// diagnostics.
func (t *RequestTracker) Len() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.requests)
}
