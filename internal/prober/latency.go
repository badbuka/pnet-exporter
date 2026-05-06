package prober

import (
	"context"
	"log/slog"
	"time"

	"pnet-exporter/internal/config"
	"pnet-exporter/internal/store"
)

type Prober struct {
	store  *store.Store
	cfg    config.LatencyConfig
	logger *slog.Logger
}

func New(store *store.Store, cfg config.LatencyConfig, logger *slog.Logger) *Prober {
	return &Prober{store: store, cfg: cfg, logger: logger}
}

func (p *Prober) Run(ctx context.Context) {
	ticker := time.NewTicker(p.cfg.Interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			p.logger.Debug("latency probing tick")
			// The ICMP namespace prober is intentionally isolated here so it can
			// be enabled per target environment without affecting core eBPF flow.
		}
	}
}
