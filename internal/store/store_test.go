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

func TestRecordResourceUsage(t *testing.T) {
	st := New(config.Default().Store)
	labels := ContainerLabels{ContainerID: "c1"}
	st.RecordResourceUsage(ResourceUsageSample{
		Container:        labels,
		CPUUsageSeconds:  2.0,
		MemoryUsageBytes: 1024,
		HasMemoryLimit:   true,
		MemoryLimitBytes: 4096,
		IOReadBytes:      512,
	})
	snap := st.Snapshot()
	if len(snap.ResourceUsage) != 1 {
		t.Fatalf("expected 1 resource usage series, got %d", len(snap.ResourceUsage))
	}
	got := snap.ResourceUsage[0]
	if got.CPUUsageSeconds != 2.0 || got.MemoryUsageBytes != 1024 || got.IOReadBytes != 512 {
		t.Fatalf("unexpected resource usage values: %+v", got)
	}
	if !got.HasMemoryLimit || got.MemoryLimitBytes != 4096 {
		t.Fatalf("expected memory limit to be carried, got %+v", got)
	}

	// Last write wins (kernel totals overwrite, not accumulate).
	st.RecordResourceUsage(ResourceUsageSample{Container: labels, CPUUsageSeconds: 5.0})
	snap = st.Snapshot()
	if len(snap.ResourceUsage) != 1 || snap.ResourceUsage[0].CPUUsageSeconds != 5.0 {
		t.Fatalf("expected overwrite to 5.0, got %#v", snap.ResourceUsage)
	}
}

func TestInboundMetrics(t *testing.T) {
	st := New(config.Default().Store)
	labels := ContainerLabels{ContainerID: "c1"}

	st.IncInboundAccept(InboundEvent{Container: labels, Source: "10.0.0.9:51000"})
	st.IncInboundActive(InboundEvent{Container: labels, Source: "10.0.0.9:51000"})
	st.IncInboundAccept(InboundEvent{Container: labels, Source: "10.0.0.9:51000"})
	st.IncInboundActive(InboundEvent{Container: labels, Source: "10.0.0.9:51000"})
	st.AddInboundBytesSent(InboundEvent{Container: labels, Source: "10.0.0.9:51000", Bytes: 100})
	st.AddInboundBytesReceived(InboundEvent{Container: labels, Source: "10.0.0.9:51000", Bytes: 250})

	snap := st.Snapshot()
	if len(snap.InboundAccepts) != 1 || snap.InboundAccepts[0].Value != 2 {
		t.Fatalf("expected accepts value 2, got %#v", snap.InboundAccepts)
	}
	if len(snap.InboundActive) != 1 || snap.InboundActive[0].Value != 2 {
		t.Fatalf("expected active value 2, got %#v", snap.InboundActive)
	}
	if snap.InboundActive[0].Source != "10.0.0.9:51000" {
		t.Fatalf("unexpected source label: %q", snap.InboundActive[0].Source)
	}
	if len(snap.InboundBytesSent) != 1 || snap.InboundBytesSent[0].Value != 100 {
		t.Fatalf("expected bytes sent 100, got %#v", snap.InboundBytesSent)
	}
	if len(snap.InboundBytesReceived) != 1 || snap.InboundBytesReceived[0].Value != 250 {
		t.Fatalf("expected bytes received 250, got %#v", snap.InboundBytesReceived)
	}

	// DecInboundActive clamps at zero.
	st.DecInboundActive(InboundEvent{Container: labels, Source: "10.0.0.9:51000"})
	st.DecInboundActive(InboundEvent{Container: labels, Source: "10.0.0.9:51000"})
	st.DecInboundActive(InboundEvent{Container: labels, Source: "10.0.0.9:51000"})
	snap = st.Snapshot()
	if snap.InboundActive[0].Value != 0 {
		t.Fatalf("expected active clamped to 0, got %f", snap.InboundActive[0].Value)
	}
}

func TestInboundSourceCardinalityBounded(t *testing.T) {
	cfg := config.Default().Store
	cfg.DestinationLimit = 1
	st := New(cfg)
	labels := ContainerLabels{ContainerID: "c1"}

	st.AddInboundBytesReceived(InboundEvent{Container: labels, Source: "10.0.0.1:1000", Bytes: 1})
	st.AddInboundBytesReceived(InboundEvent{Container: labels, Source: "10.0.0.2:1000", Bytes: 1})

	snap := st.Snapshot()
	foundOverflow := false
	for _, series := range snap.InboundBytesReceived {
		if series.Source == overflowLabel {
			foundOverflow = true
		}
	}
	if !foundOverflow {
		t.Fatal("expected overflow source series")
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
