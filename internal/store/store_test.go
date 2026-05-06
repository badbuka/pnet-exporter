package store

import (
	"testing"
	"time"

	"pnet-exporter/internal/config"
)

func TestStoreBoundsDestinations(t *testing.T) {
	cfg := config.Default().Store
	cfg.DestinationLimit = 1
	store := New(cfg)
	labels := ContainerLabels{ContainerID: "c1"}

	store.IncSuccessfulConnect(TCPEvent{Container: labels, Endpoint: Endpoint{Destination: "10.0.0.1:80"}})
	store.IncSuccessfulConnect(TCPEvent{Container: labels, Endpoint: Endpoint{Destination: "10.0.0.2:80"}})

	snapshot := store.Snapshot()
	if len(snapshot.Successful) != 2 {
		t.Fatalf("expected two series, got %d", len(snapshot.Successful))
	}

	foundOverflow := false
	for _, series := range snapshot.Successful {
		if series.Destination == overflowLabel {
			foundOverflow = true
		}
	}
	if !foundOverflow {
		t.Fatal("expected overflow destination series")
	}
}

func TestStoreProducesHistogramBuckets(t *testing.T) {
	cfg := config.Default().Store
	cfg.DurationBuckets = []float64{0.01, 0.1}
	store := New(cfg)
	labels := ContainerLabels{ContainerID: "c1"}

	store.ObserveProtocol(ProtocolEvent{
		Protocol:  ProtocolHTTP,
		Container: labels,
		Endpoint:  Endpoint{Destination: "example:80"},
		Status:    "200",
		Duration:  50 * time.Millisecond,
	})

	snapshot := store.Snapshot()
	if len(snapshot.ProtocolDur) != 1 {
		t.Fatalf("expected one protocol histogram, got %d", len(snapshot.ProtocolDur))
	}
	hist := snapshot.ProtocolDur[0]
	if hist.Sum != 0.05 || hist.Count != 1 {
		t.Fatalf("unexpected histogram sum/count: %f/%d", hist.Sum, hist.Count)
	}
	if len(hist.Buckets) != 2 || hist.Buckets[0].Count != 0 || hist.Buckets[1].Count != 1 {
		t.Fatalf("unexpected buckets: %#v", hist.Buckets)
	}
}

func TestPruneDropsOnlyMomentarySeriesByTTL(t *testing.T) {
	cfg := config.Default().Store
	cfg.MetricTTL = time.Millisecond
	store := New(cfg)
	labels := ContainerLabels{ContainerID: "c1"}

	store.IncSuccessfulConnect(TCPEvent{Container: labels, Endpoint: Endpoint{Destination: "10.0.0.1:80"}})
	store.SetActiveConnections(TCPEvent{Container: labels, Endpoint: Endpoint{Destination: "10.0.0.1:80"}, Value: 3})

	live := func() map[string]struct{} { return map[string]struct{}{"c1": {}} }
	store.Prune(time.Now().Add(time.Second), live)

	snap := store.Snapshot()
	if len(snap.Successful) != 1 {
		t.Fatalf("counter must survive TTL prune, got %d series", len(snap.Successful))
	}
	if len(snap.Active) != 0 {
		t.Fatalf("active gauge must expire by TTL, got %d series", len(snap.Active))
	}
}

func TestPruneDropsAllSeriesAndBookkeepingForVanishedContainer(t *testing.T) {
	cfg := config.Default().Store
	cfg.MetricTTL = time.Hour
	store := New(cfg)

	store.IncSuccessfulConnect(TCPEvent{
		Container: ContainerLabels{ContainerID: "c1"},
		Endpoint:  Endpoint{Destination: "10.0.0.1:80"},
	})

	if got := len(store.destinationSeen); got != 1 {
		t.Fatalf("expected destinationSeen to be populated, got %d", got)
	}

	live := func() map[string]struct{} { return map[string]struct{}{} }
	store.Prune(time.Now(), live)

	snap := store.Snapshot()
	if len(snap.Successful) != 0 {
		t.Fatalf("series for vanished container must be dropped, got %d", len(snap.Successful))
	}
	if got := len(store.destinationSeen); got != 0 {
		t.Fatalf("destinationSeen must be cleaned up, got %d", got)
	}
}
