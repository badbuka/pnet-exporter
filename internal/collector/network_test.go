package collector

import (
	"testing"
	"time"

	"pnet-exporter/internal/config"
	"pnet-exporter/internal/store"

	"github.com/prometheus/client_golang/prometheus"
)

func TestNetworkCollectorExportsStandardHistogramSeries(t *testing.T) {
	metricStore := store.New(config.Default().Store)
	metricStore.ObserveDNS(store.DNSEvent{
		Container:   store.ContainerLabels{ContainerID: "c1", ContainerName: "web"},
		Domain:      "example.com",
		RequestType: "A",
		Status:      "ok",
		Duration:    5 * time.Millisecond,
	})

	reg := prometheus.NewRegistry()
	reg.MustRegister(NewNetworkCollector(metricStore))

	families, err := reg.Gather()
	if err != nil {
		t.Fatalf("gather metrics: %v", err)
	}

	names := map[string]bool{}
	for _, family := range families {
		names[family.GetName()] = true
	}
	for _, name := range []string{
		"container_dns_requests_duration_seconds_bucket",
		"container_dns_requests_duration_seconds_sum",
		"container_dns_requests_duration_seconds_count",
	} {
		if !names[name] {
			t.Fatalf("expected metric family %s", name)
		}
	}
}
