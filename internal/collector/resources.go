package collector

import (
	"pnet-exporter/internal/store"

	"github.com/prometheus/client_golang/prometheus"
)

// ResourcesCollector exposes per-container resource-utilization metrics
// (CPU, memory, block I/O and PSI pressure) gathered from cgroup v2
// control files by internal/resources.
type ResourcesCollector struct {
	store *store.Store

	cpuUsage           *prometheus.Desc
	cpuUser            *prometheus.Desc
	cpuSystem          *prometheus.Desc
	cpuPeriods         *prometheus.Desc
	cpuThrottledPeriod *prometheus.Desc
	cpuThrottled       *prometheus.Desc

	memoryUsage *prometheus.Desc
	memoryPeak  *prometheus.Desc
	memoryLimit *prometheus.Desc

	ioReadBytes    *prometheus.Desc
	ioWrittenBytes *prometheus.Desc
	ioReads        *prometheus.Desc
	ioWrites       *prometheus.Desc

	cpuPressure    *prometheus.Desc
	memoryPressure *prometheus.Desc
	ioPressure     *prometheus.Desc
}

func NewResourcesCollector(metricStore *store.Store) *ResourcesCollector {
	pressureLabels := appendContainerLabels("level")
	return &ResourcesCollector{
		store: metricStore,
		cpuUsage: prometheus.NewDesc(
			"container_resources_cpu_usage_seconds_total",
			"Total CPU time consumed by the container, in seconds (cgroup cpu.stat usage_usec).",
			containerLabels,
			nil,
		),
		cpuUser: prometheus.NewDesc(
			"container_resources_cpu_user_seconds_total",
			"Total CPU time consumed in user mode by the container, in seconds.",
			containerLabels,
			nil,
		),
		cpuSystem: prometheus.NewDesc(
			"container_resources_cpu_system_seconds_total",
			"Total CPU time consumed in system mode by the container, in seconds.",
			containerLabels,
			nil,
		),
		cpuPeriods: prometheus.NewDesc(
			"container_resources_cpu_periods_total",
			"Total number of CPU enforcement periods that have elapsed (cgroup cpu.stat nr_periods).",
			containerLabels,
			nil,
		),
		cpuThrottledPeriod: prometheus.NewDesc(
			"container_resources_cpu_throttled_periods_total",
			"Total number of CPU enforcement periods in which the container was throttled (cgroup cpu.stat nr_throttled).",
			containerLabels,
			nil,
		),
		cpuThrottled: prometheus.NewDesc(
			"container_resources_cpu_throttled_seconds_total",
			"Total time the container was CPU-throttled, in seconds (cgroup cpu.stat throttled_usec).",
			containerLabels,
			nil,
		),
		memoryUsage: prometheus.NewDesc(
			"container_resources_memory_usage_bytes",
			"Current memory usage of the container, in bytes (cgroup memory.current).",
			containerLabels,
			nil,
		),
		memoryPeak: prometheus.NewDesc(
			"container_resources_memory_peak_bytes",
			"Peak memory usage of the container, in bytes (cgroup memory.peak).",
			containerLabels,
			nil,
		),
		memoryLimit: prometheus.NewDesc(
			"container_resources_memory_limit_bytes",
			"Memory limit of the container, in bytes (cgroup memory.max; absent when unlimited).",
			containerLabels,
			nil,
		),
		ioReadBytes: prometheus.NewDesc(
			"container_resources_io_read_bytes_total",
			"Total bytes read from block devices by the container (cgroup io.stat rbytes, summed across devices).",
			containerLabels,
			nil,
		),
		ioWrittenBytes: prometheus.NewDesc(
			"container_resources_io_written_bytes_total",
			"Total bytes written to block devices by the container (cgroup io.stat wbytes, summed across devices).",
			containerLabels,
			nil,
		),
		ioReads: prometheus.NewDesc(
			"container_resources_io_reads_total",
			"Total number of block-device read operations by the container (cgroup io.stat rios, summed across devices).",
			containerLabels,
			nil,
		),
		ioWrites: prometheus.NewDesc(
			"container_resources_io_writes_total",
			"Total number of block-device write operations by the container (cgroup io.stat wios, summed across devices).",
			containerLabels,
			nil,
		),
		cpuPressure: prometheus.NewDesc(
			"container_resources_cpu_pressure_seconds_total",
			"Total CPU pressure stall time for the container, in seconds (cgroup cpu.pressure total).",
			pressureLabels,
			nil,
		),
		memoryPressure: prometheus.NewDesc(
			"container_resources_memory_pressure_seconds_total",
			"Total memory pressure stall time for the container, in seconds (cgroup memory.pressure total).",
			pressureLabels,
			nil,
		),
		ioPressure: prometheus.NewDesc(
			"container_resources_io_pressure_seconds_total",
			"Total I/O pressure stall time for the container, in seconds (cgroup io.pressure total).",
			pressureLabels,
			nil,
		),
	}
}

func (c *ResourcesCollector) Describe(ch chan<- *prometheus.Desc) {
	for _, desc := range []*prometheus.Desc{
		c.cpuUsage,
		c.cpuUser,
		c.cpuSystem,
		c.cpuPeriods,
		c.cpuThrottledPeriod,
		c.cpuThrottled,
		c.memoryUsage,
		c.memoryPeak,
		c.memoryLimit,
		c.ioReadBytes,
		c.ioWrittenBytes,
		c.ioReads,
		c.ioWrites,
		c.cpuPressure,
		c.memoryPressure,
		c.ioPressure,
	} {
		ch <- desc
	}
}

func (c *ResourcesCollector) Collect(ch chan<- prometheus.Metric) {
	snapshot := c.store.Snapshot()
	for _, s := range snapshot.ResourceUsage {
		labels := labelValues(s.Container)
		ch <- prometheus.MustNewConstMetric(c.cpuUsage, prometheus.CounterValue, s.CPUUsageSeconds, labels...)
		ch <- prometheus.MustNewConstMetric(c.cpuUser, prometheus.CounterValue, s.CPUUserSeconds, labels...)
		ch <- prometheus.MustNewConstMetric(c.cpuSystem, prometheus.CounterValue, s.CPUSystemSeconds, labels...)
		ch <- prometheus.MustNewConstMetric(c.cpuPeriods, prometheus.CounterValue, s.CPUPeriods, labels...)
		ch <- prometheus.MustNewConstMetric(c.cpuThrottledPeriod, prometheus.CounterValue, s.CPUThrottledPeriods, labels...)
		ch <- prometheus.MustNewConstMetric(c.cpuThrottled, prometheus.CounterValue, s.CPUThrottledSeconds, labels...)

		ch <- prometheus.MustNewConstMetric(c.memoryUsage, prometheus.GaugeValue, s.MemoryUsageBytes, labels...)
		if s.HasMemoryPeak {
			ch <- prometheus.MustNewConstMetric(c.memoryPeak, prometheus.GaugeValue, s.MemoryPeakBytes, labels...)
		}
		if s.HasMemoryLimit {
			ch <- prometheus.MustNewConstMetric(c.memoryLimit, prometheus.GaugeValue, s.MemoryLimitBytes, labels...)
		}

		ch <- prometheus.MustNewConstMetric(c.ioReadBytes, prometheus.CounterValue, s.IOReadBytes, labels...)
		ch <- prometheus.MustNewConstMetric(c.ioWrittenBytes, prometheus.CounterValue, s.IOWrittenBytes, labels...)
		ch <- prometheus.MustNewConstMetric(c.ioReads, prometheus.CounterValue, s.IOReads, labels...)
		ch <- prometheus.MustNewConstMetric(c.ioWrites, prometheus.CounterValue, s.IOWrites, labels...)

		if s.HasCPUPressure {
			ch <- prometheus.MustNewConstMetric(c.cpuPressure, prometheus.CounterValue, s.CPUPressureSomeSeconds, labelValues(s.Container, "some")...)
			ch <- prometheus.MustNewConstMetric(c.cpuPressure, prometheus.CounterValue, s.CPUPressureFullSeconds, labelValues(s.Container, "full")...)
		}
		if s.HasMemoryPressure {
			ch <- prometheus.MustNewConstMetric(c.memoryPressure, prometheus.CounterValue, s.MemoryPressureSomeSeconds, labelValues(s.Container, "some")...)
			ch <- prometheus.MustNewConstMetric(c.memoryPressure, prometheus.CounterValue, s.MemoryPressureFullSeconds, labelValues(s.Container, "full")...)
		}
		if s.HasIOPressure {
			ch <- prometheus.MustNewConstMetric(c.ioPressure, prometheus.CounterValue, s.IOPressureSomeSeconds, labelValues(s.Container, "some")...)
			ch <- prometheus.MustNewConstMetric(c.ioPressure, prometheus.CounterValue, s.IOPressureFullSeconds, labelValues(s.Container, "full")...)
		}
	}
}
