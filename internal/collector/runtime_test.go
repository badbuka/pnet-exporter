package collector

import (
	"testing"

	"pnet-exporter/internal/config"
	"pnet-exporter/internal/store"

	"github.com/prometheus/client_golang/prometheus"
)

func TestRuntimeCollectorOOM(t *testing.T) {
	metricStore := store.New(config.Default().Store)
	metricStore.ObserveOOMKill(store.OOMEvent{
		Container: store.ContainerLabels{ContainerID: "c1"},
		VictimPID: 42,
	})

	reg := prometheus.NewRegistry()
	reg.MustRegister(NewRuntimeCollector(metricStore))

	families, err := reg.Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	found := false
	for _, f := range families {
		if f.GetName() == "container_oom_kills_total" {
			found = true
			if len(f.GetMetric()) != 1 || f.GetMetric()[0].GetCounter().GetValue() != 1 {
				t.Fatalf("unexpected OOM metric: %v", f.GetMetric())
			}
		}
	}
	if !found {
		t.Fatal("container_oom_kills_total not found")
	}
}

func TestRuntimeCollectorDelays(t *testing.T) {
	metricStore := store.New(config.Default().Store)
	metricStore.RecordResourceDelay(store.ResourceDelaySample{
		Container:       store.ContainerLabels{ContainerID: "c1"},
		CPUDelaySeconds: 2.0,
		IODelaySeconds:  0.5,
	})

	reg := prometheus.NewRegistry()
	reg.MustRegister(NewRuntimeCollector(metricStore))

	families, err := reg.Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	wantValues := map[string]float64{
		"container_resources_cpu_delay_seconds_total":  2.0,
		"container_resources_disk_delay_seconds_total": 0.5,
	}
	for _, f := range families {
		if want, ok := wantValues[f.GetName()]; ok {
			if len(f.GetMetric()) != 1 || f.GetMetric()[0].GetCounter().GetValue() != want {
				t.Errorf("%s: got %v, want value %f", f.GetName(), f.GetMetric(), want)
			}
			delete(wantValues, f.GetName())
		}
	}
	for name := range wantValues {
		t.Errorf("missing metric family %q", name)
	}
}
