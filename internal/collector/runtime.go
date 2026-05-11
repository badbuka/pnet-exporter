package collector

import (
	"pnet-exporter/internal/store"

	"github.com/prometheus/client_golang/prometheus"
)

// RuntimeCollector exposes container-runtime metrics (OOM kills,
// CPU and block I/O wait from schedstat/delay accounting) alongside
// the network-centric collectors.
type RuntimeCollector struct {
	store *store.Store

	oomKills *prometheus.Desc
	cpuDelay *prometheus.Desc
	ioDelay  *prometheus.Desc
}

func NewRuntimeCollector(metricStore *store.Store) *RuntimeCollector {
	return &RuntimeCollector{
		store: metricStore,
		oomKills: prometheus.NewDesc(
			"container_oom_kills_total",
			"Total number of times the OOM killer terminated a task in this container.",
			containerLabels,
			nil,
		),
		cpuDelay: prometheus.NewDesc(
			"container_resources_cpu_delay_seconds_total",
			"Total amount of time the container has been waiting for CPU, in seconds.",
			containerLabels,
			nil,
		),
		ioDelay: prometheus.NewDesc(
			"container_resources_disk_delay_seconds_total",
			"Total amount of time the container has been waiting for disk I/O, in seconds.",
			containerLabels,
			nil,
		),
	}
}

func (c *RuntimeCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.oomKills
	ch <- c.cpuDelay
	ch <- c.ioDelay
}

func (c *RuntimeCollector) Collect(ch chan<- prometheus.Metric) {
	snapshot := c.store.Snapshot()
	for _, series := range snapshot.OOMKills {
		ch <- prometheus.MustNewConstMetric(c.oomKills, prometheus.CounterValue, series.Value, labelValues(series.Container)...)
	}
	for _, series := range snapshot.Delays {
		ch <- prometheus.MustNewConstMetric(c.cpuDelay, prometheus.CounterValue, series.CPUDelaySeconds, labelValues(series.Container)...)
		ch <- prometheus.MustNewConstMetric(c.ioDelay, prometheus.CounterValue, series.IODelaySeconds, labelValues(series.Container)...)
	}
}
