package identity

import (
	"testing"
	"time"
)

func TestCacheIndexesContainers(t *testing.T) {
	cache := NewCache(time.Minute)
	container := Container{
		ID:         "abcdef",
		Name:       "web",
		PodID:      "pod1",
		PID:        123,
		CgroupID:   456,
		NetNSInode: 789,
	}
	cache.Replace([]Container{container})

	if got, ok := cache.ByPID(123); !ok || got.ID != container.ID {
		t.Fatalf("expected pid index to return container, got %#v ok=%v", got, ok)
	}
	if got, ok := cache.ByCgroupID(456); !ok || got.ID != container.ID {
		t.Fatalf("expected cgroup index to return container, got %#v ok=%v", got, ok)
	}
	if got, ok := cache.ByNetNS(789); !ok || got.ID != container.ID {
		t.Fatalf("expected netns index to return container, got %#v ok=%v", got, ok)
	}
}

func TestLabelsForUnknownContainer(t *testing.T) {
	cache := NewCache(time.Minute)
	labels := cache.LabelsFor("missing")
	if labels.ContainerID != "missing" || labels.ContainerName != "" || labels.PodID != "" {
		t.Fatalf("unexpected labels: %#v", labels)
	}
}

func TestUpsertAddsAndUpdates(t *testing.T) {
	cache := NewCache(time.Minute)
	c := Container{ID: "c1", Name: "web", PID: 10, CgroupID: 20, NetNSInode: 30}
	cache.Upsert(c)

	if got, ok := cache.ByPID(10); !ok || got.ID != "c1" {
		t.Fatalf("ByPID after Upsert: got %v ok=%v", got, ok)
	}
	if got, ok := cache.ByCgroupID(20); !ok || got.ID != "c1" {
		t.Fatalf("ByCgroupID after Upsert: got %v ok=%v", got, ok)
	}
	if got, ok := cache.ByNetNS(30); !ok || got.ID != "c1" {
		t.Fatalf("ByNetNS after Upsert: got %v ok=%v", got, ok)
	}

	c.Name = "web-v2"
	cache.Upsert(c)
	if got, ok := cache.ByPID(10); !ok || got.Name != "web-v2" {
		t.Fatalf("ByPID after second Upsert: name=%q ok=%v", got.Name, ok)
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

func TestByNetNSMiss(t *testing.T) {
	cache := NewCache(time.Minute)
	if _, ok := cache.ByNetNS(99999); ok {
		t.Fatal("expected miss for unknown net NS inode")
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
