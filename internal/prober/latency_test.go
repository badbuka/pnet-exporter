package prober

import (
	"context"
	"log/slog"
	"testing"
	"time"

	"pnet-exporter/internal/config"
	"pnet-exporter/internal/identity"
	"pnet-exporter/internal/store"
)

func TestTargetsForCollectsContainerIPs(t *testing.T) {
	metricStore := store.New(config.Default().Store)
	metricStore.IncSuccessfulConnect(store.TCPEvent{
		Container: store.ContainerLabels{ContainerID: "c1"},
		Endpoint:  store.Endpoint{Destination: "10.0.0.1:443"},
	})
	metricStore.IncSuccessfulConnect(store.TCPEvent{
		Container: store.ContainerLabels{ContainerID: "c1"},
		Endpoint:  store.Endpoint{Destination: "10.0.0.1:443", ActualDestination: "10.0.0.2:443"},
	})
	// Other containers and non-IP destinations must be ignored.
	metricStore.IncSuccessfulConnect(store.TCPEvent{
		Container: store.ContainerLabels{ContainerID: "c2"},
		Endpoint:  store.Endpoint{Destination: "10.9.9.9:443"},
	})
	metricStore.IncSuccessfulConnect(store.TCPEvent{
		Container: store.ContainerLabels{ContainerID: "c1"},
		Endpoint:  store.Endpoint{Destination: "not-an-ip:443"},
	})

	p := New(metricStore, nil, config.LatencyConfig{MaxTargetsPerTick: 10}, slog.Default())
	targets := p.targetsFor(identity.Container{ID: "c1"})

	got := map[string]bool{}
	for _, target := range targets {
		got[target] = true
	}
	if len(got) != 2 || !got["10.0.0.1"] || !got["10.0.0.2"] {
		t.Fatalf("targets: got %v", targets)
	}
}

func TestTargetsForRespectsMaxPerTick(t *testing.T) {
	metricStore := store.New(config.Default().Store)
	labels := store.ContainerLabels{ContainerID: "c1"}
	for i := 1; i <= 5; i++ {
		metricStore.IncSuccessfulConnect(store.TCPEvent{
			Container: labels,
			Endpoint:  store.Endpoint{Destination: "10.0.0." + string(rune('0'+i)) + ":443"},
		})
	}

	p := New(metricStore, nil, config.LatencyConfig{MaxTargetsPerTick: 2}, slog.Default())
	if targets := p.targetsFor(identity.Container{ID: "c1"}); len(targets) != 2 {
		t.Fatalf("expected 2 targets, got %d", len(targets))
	}
}

func TestNextIDWrapsAndIncrements(t *testing.T) {
	p := New(store.New(config.Default().Store), nil, config.LatencyConfig{}, slog.Default())
	first := p.nextID()
	if second := p.nextID(); second != first+1 {
		t.Fatalf("nextID must increment: %d then %d", first, second)
	}
	p.seq.Store(0xFFFF)
	if id := p.nextID(); id != 0 {
		t.Fatalf("nextID must wrap to 0, got %d", id)
	}
}

func TestRunStopsOnContextCancel(t *testing.T) {
	p := New(store.New(config.Default().Store), identity.NewCache(time.Minute),
		config.LatencyConfig{Interval: time.Millisecond}, slog.Default())
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		p.Run(ctx)
		close(done)
	}()
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("prober did not stop after context cancel")
	}
}
