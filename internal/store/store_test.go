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

func TestObserveDNSCounterAndHistogram(t *testing.T) {
	cfg := config.Default().Store
	st := New(cfg)
	labels := ContainerLabels{ContainerID: "c1"}
	event := DNSEvent{Container: labels, Domain: "example.com", RequestType: "A", Status: "ok", Duration: 0}

	st.ObserveDNS(event)
	st.ObserveDNS(event)
	snap := st.Snapshot()
	if len(snap.DNSRequests) != 1 || snap.DNSRequests[0].Value != 2 {
		t.Fatalf("expected 1 series with value 2, got %#v", snap.DNSRequests)
	}
	if len(snap.DNSDurations) != 0 {
		t.Fatalf("expected no DNS histogram for zero-duration events, got %d", len(snap.DNSDurations))
	}

	eventWithDuration := event
	eventWithDuration.Duration = 10 * time.Millisecond
	st.ObserveDNS(eventWithDuration)
	snap = st.Snapshot()
	if len(snap.DNSDurations) != 1 || snap.DNSDurations[0].Count != 1 {
		t.Fatalf("expected 1 DNS histogram entry with count 1, got %#v", snap.DNSDurations)
	}
	if snap.DNSDurations[0].Sum != 0.01 {
		t.Fatalf("unexpected DNS histogram sum: %f", snap.DNSDurations[0].Sum)
	}
}

func TestObserveOOMKill(t *testing.T) {
	st := New(config.Default().Store)
	labels := ContainerLabels{ContainerID: "c1"}
	st.ObserveOOMKill(OOMEvent{Container: labels, VictimPID: 42})
	st.ObserveOOMKill(OOMEvent{Container: labels, VictimPID: 43})
	st.ObserveOOMKill(OOMEvent{Container: labels, VictimPID: 44})
	snap := st.Snapshot()
	if len(snap.OOMKills) != 1 || snap.OOMKills[0].Value != 3 {
		t.Fatalf("expected 1 OOM series with value 3, got %#v", snap.OOMKills)
	}
}

func TestRecordResourceDelay(t *testing.T) {
	st := New(config.Default().Store)
	labels := ContainerLabels{ContainerID: "c1"}
	st.RecordResourceDelay(ResourceDelaySample{Container: labels, CPUDelaySeconds: 1.5, IODelaySeconds: 0.3})
	snap := st.Snapshot()
	if len(snap.Delays) != 1 {
		t.Fatalf("expected 1 delay series, got %d", len(snap.Delays))
	}
	if snap.Delays[0].CPUDelaySeconds != 1.5 || snap.Delays[0].IODelaySeconds != 0.3 {
		t.Fatalf("unexpected delay values: %+v", snap.Delays[0])
	}
}

func TestSetLatencyLastWriteWins(t *testing.T) {
	st := New(config.Default().Store)
	labels := ContainerLabels{ContainerID: "c1"}
	st.SetLatency(LatencySample{Container: labels, DestinationIP: "10.0.0.1", Seconds: 0.042})
	st.SetLatency(LatencySample{Container: labels, DestinationIP: "10.0.0.1", Seconds: 0.100})
	snap := st.Snapshot()
	if len(snap.Latency) != 1 {
		t.Fatalf("expected 1 latency series, got %d", len(snap.Latency))
	}
	if snap.Latency[0].Value != 0.100 {
		t.Fatalf("expected last-write value 0.100, got %f", snap.Latency[0].Value)
	}
}

func TestSetIPFQDN(t *testing.T) {
	st := New(config.Default().Store)
	labels := ContainerLabels{ContainerID: "c1"}
	st.SetIPFQDN(IPFQDNMapping{Container: labels, IP: "10.0.0.1", FQDN: "a.example.com", Value: 1})
	st.SetIPFQDN(IPFQDNMapping{Container: labels, IP: "10.0.0.2", FQDN: "b.example.com", Value: 1})
	st.SetIPFQDN(IPFQDNMapping{Container: labels, IP: "10.0.0.1", FQDN: "a.example.com", Value: 1})
	snap := st.Snapshot()
	if len(snap.IPToFQDN) != 2 {
		t.Fatalf("expected 2 FQDN entries, got %d", len(snap.IPToFQDN))
	}
}

func TestObserveProtocolHistogram(t *testing.T) {
	cfg := config.Default().Store
	cfg.DurationBuckets = []float64{0.1, 1.0}
	st := New(cfg)
	labels := ContainerLabels{ContainerID: "c1"}
	st.ObserveProtocol(ProtocolEvent{
		Protocol:  ProtocolHTTP,
		Container: labels,
		Endpoint:  Endpoint{Destination: "svc:80"},
		Status:    "200",
		Duration:  50 * time.Millisecond,
	})
	snap := st.Snapshot()
	if len(snap.ProtocolDur) != 1 || snap.ProtocolDur[0].Count != 1 {
		t.Fatalf("expected 1 protocol histogram with count 1, got %#v", snap.ProtocolDur)
	}
}

func TestPruneDropsLatencyByTTL(t *testing.T) {
	cfg := config.Default().Store
	cfg.MetricTTL = time.Millisecond
	st := New(cfg)
	labels := ContainerLabels{ContainerID: "c1"}
	st.SetLatency(LatencySample{Container: labels, DestinationIP: "10.0.0.1", Seconds: 0.005})

	live := func() map[string]struct{} { return map[string]struct{}{"c1": {}} }
	st.Prune(time.Now().Add(time.Second), live)

	snap := st.Snapshot()
	if len(snap.Latency) != 0 {
		t.Fatalf("expected latency to be pruned by TTL, got %d series", len(snap.Latency))
	}
}

func TestFQDNCeilingOverflow(t *testing.T) {
	cfg := config.Default().Store
	cfg.FQDNCeiling = 1
	st := New(cfg)
	labels := ContainerLabels{ContainerID: "c1"}
	st.SetIPFQDN(IPFQDNMapping{Container: labels, IP: "1.2.3.4", FQDN: "first.example.com", Value: 1})
	st.SetIPFQDN(IPFQDNMapping{Container: labels, IP: "5.6.7.8", FQDN: "second.example.com", Value: 1})

	snap := st.Snapshot()
	if len(snap.IPToFQDN) != 2 {
		t.Fatalf("expected 2 entries (one overflow), got %d", len(snap.IPToFQDN))
	}
	overflowFound := false
	for _, s := range snap.IPToFQDN {
		if s.FQDN == "~other" {
			overflowFound = true
		}
	}
	if !overflowFound {
		t.Fatal("expected ~other overflow entry for second FQDN")
	}
}
