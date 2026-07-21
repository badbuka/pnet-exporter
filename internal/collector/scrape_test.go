package collector

import (
	"testing"

	"pnet-exporter/internal/config"
	"pnet-exporter/internal/store"

	"github.com/prometheus/client_golang/prometheus"
)

// gatherValues gathers reg and returns a name → sum of sample values map.
func gatherValues(t *testing.T, reg *prometheus.Registry) map[string]float64 {
	t.Helper()
	families, err := reg.Gather()
	if err != nil {
		t.Fatalf("gather metrics: %v", err)
	}
	out := map[string]float64{}
	for _, family := range families {
		var total float64
		for _, metric := range family.GetMetric() {
			if g := metric.GetGauge(); g != nil {
				total += g.GetValue()
			}
			if c := metric.GetCounter(); c != nil {
				total += c.GetValue()
			}
		}
		out[family.GetName()] = total
	}
	return out
}

func TestNetworkCollectorExportsTCPAndInboundSeries(t *testing.T) {
	metricStore := store.New(config.Default().Store)
	labels := store.ContainerLabels{ContainerID: "c1", ContainerName: "web"}
	event := store.TCPEvent{Container: labels, Endpoint: store.Endpoint{Destination: "10.0.0.1:443"}, Bytes: 64}

	metricStore.ObserveListen(store.ListenEndpoint{Container: labels, ListenAddr: "0.0.0.0:8080", Value: 1})
	metricStore.IncSuccessfulConnect(event)
	metricStore.IncFailedConnect(event)
	metricStore.IncRetransmit(event)
	metricStore.IncActiveConnection(event)
	metricStore.AddBytesSent(event)
	metricStore.AddBytesReceived(event)
	metricStore.IncInboundAccept(store.InboundEvent{Container: labels, Source: "203.0.113.7:51234", Bytes: 64})
	metricStore.IncInboundActive(store.InboundEvent{Container: labels, Source: "203.0.113.7:51234"})

	reg := prometheus.NewRegistry()
	reg.MustRegister(NewNetworkCollector(metricStore))

	got := gatherValues(t, reg)
	want := map[string]float64{
		"container_net_tcp_listen_info":                  1,
		"container_net_tcp_successful_connects_total":    1,
		"container_net_tcp_failed_connects_total":        1,
		"container_net_tcp_retransmits_total":            1,
		"container_net_tcp_active_connections":           1,
		"container_net_tcp_bytes_sent_total":             64,
		"container_net_tcp_bytes_received_total":         64,
		"container_net_tcp_inbound_accepts_total":        1,
		"container_net_tcp_inbound_active_connections":   1,
	}
	for name, value := range want {
		if got[name] != value {
			t.Errorf("%s: got %v, want %v", name, got[name], value)
		}
	}
}

func TestResourcesCollectorExportsUsageAndPressure(t *testing.T) {
	metricStore := store.New(config.Default().Store)
	metricStore.RecordResourceUsage(store.ResourceUsageSample{
		Container:                  store.ContainerLabels{ContainerID: "c1", ContainerName: "web"},
		CPUUsageSeconds:            12.5,
		MemoryUsageBytes:           4096,
		MemoryPeakBytes:            8192,
		HasMemoryPeak:              true,
		IOReadBytes:                1000,
		IOWrittenBytes:             2000,
		CPUPressureSomeSeconds:     0.5,
		HasCPUPressure:             true,
	})

	reg := prometheus.NewRegistry()
	reg.MustRegister(NewResourcesCollector(metricStore))

	got := gatherValues(t, reg)
	want := map[string]float64{
		"container_resources_cpu_usage_seconds_total":        12.5,
		"container_resources_memory_usage_bytes":             4096,
		"container_resources_memory_peak_bytes":              8192,
		"container_resources_io_read_bytes_total":            1000,
		"container_resources_io_written_bytes_total":         2000,
		"container_resources_cpu_pressure_seconds_total":     0.5,
	}
	for name, value := range want {
		if got[name] != value {
			t.Errorf("%s: got %v, want %v", name, got[name], value)
		}
	}

	// Optional readings without their Has* flag must not be emitted.
	if _, ok := got["container_resources_memory_limit_bytes"]; ok {
		t.Error("memory limit must be absent when HasMemoryLimit is false")
	}
	if _, ok := got["container_resources_memory_pressure_seconds_total"]; ok {
		t.Error("memory pressure must be absent when HasMemoryPressure is false")
	}
}
