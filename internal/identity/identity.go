package identity

import (
	"sync"
	"time"
)

type Container struct {
	ID           string
	Name         string
	PodID        string
	PID          int
	CgroupID     uint64
	CgroupPath   string
	LastObserved time.Time
}

type Cache struct {
	mu       sync.RWMutex
	ttl      time.Duration
	byID     map[string]Container
	byPID    map[int]string
	byCgroup map[uint64]string
}

func NewCache(ttl time.Duration) *Cache {
	return &Cache{
		ttl:      ttl,
		byID:     make(map[string]Container),
		byPID:    make(map[int]string),
		byCgroup: make(map[uint64]string),
	}
}

func (c *Cache) Replace(containers []Container) {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	nextIDs := make(map[string]struct{}, len(containers))
	for _, container := range containers {
		container.LastObserved = now
		c.byID[container.ID] = container
		nextIDs[container.ID] = struct{}{}
	}

	for id, container := range c.byID {
		if _, ok := nextIDs[id]; ok {
			continue
		}
		if now.Sub(container.LastObserved) > c.ttl {
			delete(c.byID, id)
		}
	}

	c.reindex()
}

func (c *Cache) ByPID(pid int) (Container, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	id, ok := c.byPID[pid]
	if !ok {
		return Container{}, false
	}
	container, ok := c.byID[id]
	return container, ok
}

func (c *Cache) ByCgroupID(cgroupID uint64) (Container, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	id, ok := c.byCgroup[cgroupID]
	if !ok {
		return Container{}, false
	}
	container, ok := c.byID[id]
	return container, ok
}

func (c *Cache) Snapshot() []Container {
	c.mu.RLock()
	defer c.mu.RUnlock()

	containers := make([]Container, 0, len(c.byID))
	for _, container := range c.byID {
		containers = append(containers, container)
	}
	return containers
}

// LiveContainerIDs returns the set of container IDs currently known to the
// cache. The returned map is owned by the caller and is safe to mutate.
func (c *Cache) LiveContainerIDs() map[string]struct{} {
	c.mu.RLock()
	defer c.mu.RUnlock()

	ids := make(map[string]struct{}, len(c.byID))
	for id := range c.byID {
		ids[id] = struct{}{}
	}
	return ids
}

func (c *Cache) reindex() {
	c.byPID = make(map[int]string, len(c.byID))
	c.byCgroup = make(map[uint64]string, len(c.byID))

	for id, container := range c.byID {
		if container.PID > 0 {
			c.byPID[container.PID] = id
		}
		if container.CgroupID > 0 {
			c.byCgroup[container.CgroupID] = id
		}
	}
}
