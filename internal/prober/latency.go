// Package prober implements a per-container ICMP latency probe.
//
// On each tick the prober iterates the live container set, enters the
// container's network namespace on a locked OS thread, and issues an
// ICMP echo to every destination IP the BPF layer has recorded for that
// container. RTT samples are written to the store as
// `container_net_latency_seconds`.
package prober

import (
	"context"
	"log/slog"
	"net"
	"sync/atomic"
	"time"

	"pnet-exporter/internal/config"
	"pnet-exporter/internal/identity"
	"pnet-exporter/internal/store"
)

// Prober samples ICMP round-trip-time per container.
type Prober struct {
	store    *store.Store
	cfg      config.LatencyConfig
	identity *identity.Cache
	logger   *slog.Logger
	seq      atomic.Uint32
}

// New returns a Prober configured for the given store, identity cache
// and latency parameters.
func New(metricStore *store.Store, ident *identity.Cache, cfg config.LatencyConfig, logger *slog.Logger) *Prober {
	return &Prober{
		store:    metricStore,
		cfg:      cfg,
		identity: ident,
		logger:   logger,
	}
}

// Run blocks until ctx is cancelled, sampling each container on every
// ticker tick. Errors from individual containers are logged but never
// fatal.
func (p *Prober) Run(ctx context.Context) {
	ticker := time.NewTicker(p.cfg.Interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			p.tick(ctx)
		}
	}
}

func (p *Prober) tick(ctx context.Context) {
	if p.identity == nil {
		return
	}
	containers := p.identity.Snapshot()
	for _, container := range containers {
		select {
		case <-ctx.Done():
			return
		default:
		}
		if container.PID == 0 {
			continue
		}
		targets := p.targetsFor(container)
		if len(targets) == 0 {
			continue
		}
		p.probeContainer(container, targets)
	}
}

// targetsFor returns the set of destination IPs to probe for one
// container. It consults the existing per-endpoint series in the store
// so the prober only walks destinations the BPF layer has already
// recorded traffic to. MaxTargetsPerTick caps the number probed each
// cycle.
func (p *Prober) targetsFor(container identity.Container) []string {
	snapshot := p.store.Snapshot()
	seen := map[string]struct{}{}
	collect := func(dest string) {
		if dest == "" {
			return
		}
		host, _, err := net.SplitHostPort(dest)
		if err != nil {
			return
		}
		if ip := net.ParseIP(host); ip == nil {
			return
		}
		seen[host] = struct{}{}
	}
	for _, series := range snapshot.Successful {
		if series.Container.ContainerID == container.ID {
			collect(series.Destination)
			collect(series.ActualDestination)
		}
	}
	for _, series := range snapshot.Active {
		if series.Container.ContainerID == container.ID {
			collect(series.Destination)
			collect(series.ActualDestination)
		}
	}

	targets := make([]string, 0, len(seen))
	for ip := range seen {
		targets = append(targets, ip)
		if p.cfg.MaxTargetsPerTick > 0 && len(targets) >= p.cfg.MaxTargetsPerTick {
			break
		}
	}
	return targets
}

func (p *Prober) probeContainer(container identity.Container, targets []string) {
	results, err := pingFromNetns(container.PID, targets, p.cfg.Timeout, p.nextID())
	if err != nil {
		p.logger.Debug("probe failed", "container", container.ID, "error", err)
		return
	}
	labels := store.ContainerLabels{
		ContainerID:   container.ID,
		ContainerName: container.Name,
		PodID:         container.PodID,
	}
	for ip, rtt := range results {
		if rtt <= 0 {
			continue
		}
		p.store.SetLatency(store.LatencySample{
			Container:     labels,
			DestinationIP: ip,
			Seconds:       rtt.Seconds(),
		})
	}
}

func (p *Prober) nextID() uint16 {
	v := p.seq.Add(1)
	return uint16(v & 0xFFFF)
}
