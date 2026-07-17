package identity

import (
	"testing"
	"time"
)

func TestCacheIndexesContainers(t *testing.T) {
	cache := NewCache(time.Minute)
	container := Container{
		ID:       "abcdef",
		Name:     "web",
		PodID:    "pod1",
		PID:      123,
		CgroupID: 456,
	}
	cache.Replace([]Container{container})

	if got, ok := cache.ByPID(123); !ok || got.ID != container.ID {
		t.Fatalf("expected pid index to return container, got %#v ok=%v", got, ok)
	}
	if got, ok := cache.ByCgroupID(456); !ok || got.ID != container.ID {
		t.Fatalf("expected cgroup index to return container, got %#v ok=%v", got, ok)
	}
}

func TestReplaceExpiresByTTL(t *testing.T) {
	cache := NewCache(time.Nanosecond)
	c := Container{ID: "c1", PID: 1}
	cache.Replace([]Container{c})
	time.Sleep(time.Millisecond)
	cache.Replace([]Container{})

	if _, ok := cache.ByPID(1); ok {
		t.Fatal("expected container to be expired after TTL")
	}
}

func TestLiveContainerIDs(t *testing.T) {
	cache := NewCache(time.Minute)
	cache.Replace([]Container{
		{ID: "c1", PID: 1},
		{ID: "c2", PID: 2},
	})
	ids := cache.LiveContainerIDs()
	if len(ids) != 2 {
		t.Fatalf("expected 2 IDs, got %d", len(ids))
	}
	if _, ok := ids["c1"]; !ok {
		t.Fatal("c1 missing from LiveContainerIDs")
	}
	if _, ok := ids["c2"]; !ok {
		t.Fatal("c2 missing from LiveContainerIDs")
	}
	// Returned map is a copy — mutating it must not affect the cache.
	delete(ids, "c1")
	if _, ok := cache.ByPID(1); !ok {
		t.Fatal("mutating returned map must not affect cache")
	}
}
