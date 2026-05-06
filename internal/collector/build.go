package collector

import (
	"runtime"

	"github.com/prometheus/client_golang/prometheus"
)

var (
	version = "dev"
	commit  = "unknown"
)

type BuildCollector struct {
	info *prometheus.Desc
}

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
