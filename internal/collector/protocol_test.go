package collector

import (
	"testing"
	"time"

	"pnet-exporter/internal/config"
	"pnet-exporter/internal/store"

	"github.com/prometheus/client_golang/prometheus"
)

func TestProtocolCollectorExportsRequests(t *testing.T) {
	metricStore := store.New(config.Default().Store)
	labels := store.ContainerLabels{ContainerID: "c1", ContainerName: "svc"}
	endpoint := store.Endpoint{Destination: "backend:80"}

	for _, proto := range []store.Protocol{store.ProtocolHTTP, store.ProtocolPostgres, store.ProtocolRedis, store.ProtocolKafka} {
		metricStore.ObserveProtocol(store.ProtocolEvent{
			Protocol:  proto,
			Container: labels,
			Endpoint:  endpoint,
			Status:    "ok",
			Duration:  0,
		})
	}

	reg := prometheus.NewRegistry()
	reg.MustRegister(NewProtocolCollector(metricStore))

	families, err := reg.Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	names := make(map[string]bool)
	for _, f := range families {
		names[f.GetName()] = true
	}
	for _, expected := range []string{
		"container_http_requests_total",
		"container_postgres_queries_total",
		"container_redis_queries_total",
		"container_kafka_requests_total",
	} {
		if !names[expected] {
			t.Errorf("missing metric family %q", expected)
		}
	}
}

func TestProtocolCollectorExportsHTTPURLLabel(t *testing.T) {
	metricStore := store.New(config.Default().Store)
	metricStore.ObserveProtocol(store.ProtocolEvent{
		Protocol:  store.ProtocolHTTP,
		Container: store.ContainerLabels{ContainerID: "c1"},
		Endpoint:  store.Endpoint{Destination: "backend:80"},
		Status:    "200",
		URL:       "example.com/api",
	})

	reg := prometheus.NewRegistry()
	reg.MustRegister(NewProtocolCollector(metricStore))

	families, err := reg.Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}

	var got string
	for _, f := range families {
		if f.GetName() != "container_http_requests_total" {
			continue
		}
		for _, m := range f.GetMetric() {
			for _, label := range m.GetLabel() {
				if label.GetName() == "url" {
					got = label.GetValue()
				}
			}
		}
	}
	if got != "example.com/api" {
		t.Fatalf("url label = %q; want %q", got, "example.com/api")
	}
}

func TestProtocolCollectorExportsDurationHistogram(t *testing.T) {
	metricStore := store.New(config.Default().Store)
	metricStore.ObserveProtocol(store.ProtocolEvent{
		Protocol:  store.ProtocolHTTP,
		Container: store.ContainerLabels{ContainerID: "c1"},
		Endpoint:  store.Endpoint{Destination: "svc:80"},
		Status:    "200",
		Duration:  50 * time.Millisecond,
	})

	reg := prometheus.NewRegistry()
	reg.MustRegister(NewProtocolCollector(metricStore))

	families, err := reg.Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	names := make(map[string]bool)
	for _, f := range families {
		names[f.GetName()] = true
	}
	for _, expected := range []string{
		"container_http_requests_duration_seconds_bucket",
		"container_http_requests_duration_seconds_sum",
		"container_http_requests_duration_seconds_count",
	} {
		if !names[expected] {
			t.Errorf("missing histogram family %q", expected)
		}
	}
}
