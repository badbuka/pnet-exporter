package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"pnet-exporter/internal/collector"
	"pnet-exporter/internal/config"
	"pnet-exporter/internal/ebpf"
	"pnet-exporter/internal/identity"
	"pnet-exporter/internal/podman"
	"pnet-exporter/internal/prober"
	"pnet-exporter/internal/store"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

func main() {
	cfg, err := config.Load()
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: cfg.LogLevel}))
	if err != nil {
		logger.Error("load configuration", "error", err)
		os.Exit(1)
	}

	if err := run(cfg, logger); err != nil {
		logger.Error("exporter stopped", "error", err)
		os.Exit(1)
	}
}

func run(cfg config.Config, logger *slog.Logger) error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if err := cfg.Validate(); err != nil {
		return err
	}

	checks := ebpf.CheckKernelSupport(cfg.SysFS)
	for _, check := range checks {
		if check.Err != nil && check.Required {
			return check.Err
		}
		if check.Err != nil {
			logger.Warn("startup check failed", "check", check.Name, "error", check.Err)
			continue
		}
		logger.Debug("startup check passed", "check", check.Name)
	}

	identityCache := identity.NewCache(cfg.ContainerTTL)
	discoverer := podman.NewDiscoverer(cfg.PodmanSocket, cfg.PodmanBinary, logger)
	metricStore := store.New(cfg.Store)

	if err := refreshContainers(ctx, discoverer, identityCache, logger); err != nil {
		logger.Warn("initial podman discovery failed", "error", err)
	}

	loader := ebpf.NewLoader(cfg.EBPF, identityCache, metricStore, logger)
	if cfg.Features.Network {
		if err := loader.Start(ctx); err != nil {
			return err
		}
		defer loader.Close()
	}

	latencyProber := prober.New(metricStore, cfg.Latency, logger)
	if cfg.Features.Latency {
		go latencyProber.Run(ctx)
	}

	go runDiscoveryLoop(ctx, cfg, discoverer, identityCache, logger)
	go metricStore.RunJanitor(ctx, cfg.Store.CleanupInterval)

	reg := prometheus.NewRegistry()
	reg.MustRegister(
		collector.NewNetworkCollector(metricStore),
		collector.NewProtocolCollector(metricStore),
		collector.NewBuildCollector(),
	)

	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{}))
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok\n"))
	})

	server := &http.Server{
		Addr:              cfg.ListenAddress,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		logger.Info("starting exporter", "listen_address", cfg.ListenAddress)
		errCh <- server.ListenAndServe()
	}()

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
		defer cancel()
		return server.Shutdown(shutdownCtx)
	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}

func runDiscoveryLoop(ctx context.Context, cfg config.Config, discoverer *podman.Discoverer, cache *identity.Cache, logger *slog.Logger) {
	ticker := time.NewTicker(cfg.DiscoveryInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := refreshContainers(ctx, discoverer, cache, logger); err != nil {
				logger.Warn("podman discovery failed", "error", err)
			}
		}
	}
}

func refreshContainers(ctx context.Context, discoverer *podman.Discoverer, cache *identity.Cache, logger *slog.Logger) error {
	containers, err := discoverer.List(ctx)
	if err != nil {
		return err
	}

	cache.Replace(containers)
	logger.Debug("container cache refreshed", "containers", len(containers))
	return nil
}
