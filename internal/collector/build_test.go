package collector

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
)

func TestBuildCollectorExportsInfo(t *testing.T) {
	reg := prometheus.NewRegistry()
	reg.MustRegister(NewBuildCollector())

	families, err := reg.Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	if len(families) != 1 {
		t.Fatalf("expected 1 metric family, got %d", len(families))
	}
	family := families[0]
	if family.GetName() != "pnet_exporter_build_info" {
		t.Fatalf("unexpected metric name: %q", family.GetName())
	}
	metrics := family.GetMetric()
	if len(metrics) != 1 {
		t.Fatalf("expected 1 metric, got %d", len(metrics))
	}
	if metrics[0].GetGauge().GetValue() != 1.0 {
		t.Fatalf("expected gauge value 1.0, got %f", metrics[0].GetGauge().GetValue())
	}
	labelMap := make(map[string]string)
	for _, lp := range metrics[0].GetLabel() {
		labelMap[lp.GetName()] = lp.GetValue()
	}
	for _, required := range []string{"version", "commit", "go_version"} {
		if _, ok := labelMap[required]; !ok {
			t.Fatalf("missing label %q", required)
		}
	}
}
