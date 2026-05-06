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
