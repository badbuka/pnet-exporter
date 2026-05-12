package collector

import (
	"runtime"

	"github.com/prometheus/client_golang/prometheus"
)

var (
	version = "dev"
	commit  = "unknown"
)

// BuildCollector is a prometheus.Collector that emits a single gauge carrying build metadata (version, commit, Go runtime version).
type BuildCollector struct {
	info *prometheus.Desc
}

// NewBuildCollector returns a BuildCollector ready to register with a Prometheus registry.
func NewBuildCollector() *BuildCollector {
	return &BuildCollector{
		info: prometheus.NewDesc(
			"pnet_exporter_build_info",
			"Build information for pnet-exporter.",
			[]string{"node_hostname", "version", "commit", "go_version"},
			nil,
		),
	}
}

func (c *BuildCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.info
}

func (c *BuildCollector) Collect(ch chan<- prometheus.Metric) {
	ch <- prometheus.MustNewConstMetric(c.info, prometheus.GaugeValue, 1, nodeHostname, version, commit, runtime.Version())
}
