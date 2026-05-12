package node

import (
	"log/slog"

	"github.com/prometheus/client_golang/prometheus"
)

const clockTicksPerSecond = 100.0

// Collector implements prometheus.Collector by reading /proc on each
// scrape. Reading is cheap (single-digit ms on typical Linux hosts) so
// no caching is performed.
type Collector struct {
	procRoot string
	logger   *slog.Logger
	hostname string

	cpuSeconds       *prometheus.Desc
	memoryTotal      *prometheus.Desc
	memoryAvailable  *prometheus.Desc
	memoryFree       *prometheus.Desc
	memoryCached     *prometheus.Desc
	uptime           *prometheus.Desc
	diskReadsTotal   *prometheus.Desc
	diskWritesTotal  *prometheus.Desc
	diskReadBytes    *prometheus.Desc
	diskWrittenBytes *prometheus.Desc
	netRxBytes       *prometheus.Desc
	netTxBytes       *prometheus.Desc
	netRxErrors      *prometheus.Desc
	netTxErrors      *prometheus.Desc
}

// NewCollector returns a node-runtime collector that reads /proc rooted
// at procRoot (defaults to "/proc"). The hostname label is shared with
// the rest of the exporter's metrics for cross-collector joins.
func NewCollector(procRoot, hostname string, logger *slog.Logger) *Collector {
	if procRoot == "" {
		procRoot = "/proc"
	}
	hostLabels := []string{"node_hostname"}
	withMode := []string{"node_hostname", "mode"}
	diskLabels := []string{"node_hostname", "device"}
	netLabels := []string{"node_hostname", "interface"}

	return &Collector{
		procRoot: procRoot,
		hostname: hostname,
		logger:   logger,
		cpuSeconds: prometheus.NewDesc(
			"node_cpu_seconds_total",
			"Aggregate /proc/stat cpu times in seconds, split by mode.",
			withMode, nil,
		),
		memoryTotal:     prometheus.NewDesc("node_memory_total_bytes", "Total physical memory in bytes.", hostLabels, nil),
		memoryAvailable: prometheus.NewDesc("node_memory_available_bytes", "Estimated available memory for new allocations.", hostLabels, nil),
		memoryFree:      prometheus.NewDesc("node_memory_free_bytes", "Memory not used by the kernel or processes.", hostLabels, nil),
		memoryCached:    prometheus.NewDesc("node_memory_cached_bytes", "Memory held in the page cache.", hostLabels, nil),
		uptime:          prometheus.NewDesc("node_uptime_seconds", "Time since the kernel finished booting.", hostLabels, nil),
		diskReadsTotal:  prometheus.NewDesc("node_disk_reads_total", "Number of completed disk reads per device.", diskLabels, nil),
		diskWritesTotal: prometheus.NewDesc("node_disk_writes_total", "Number of completed disk writes per device.", diskLabels, nil),
		diskReadBytes:   prometheus.NewDesc("node_disk_read_bytes_total", "Total bytes read per disk device.", diskLabels, nil),
		diskWrittenBytes: prometheus.NewDesc("node_disk_written_bytes_total",
			"Total bytes written per disk device.", diskLabels, nil),
		netRxBytes:  prometheus.NewDesc("node_network_receive_bytes_total", "Total bytes received per network interface.", netLabels, nil),
		netTxBytes:  prometheus.NewDesc("node_network_transmit_bytes_total", "Total bytes transmitted per network interface.", netLabels, nil),
		netRxErrors: prometheus.NewDesc("node_network_receive_errors_total", "Total receive errors per network interface.", netLabels, nil),
		netTxErrors: prometheus.NewDesc("node_network_transmit_errors_total", "Total transmit errors per network interface.", netLabels, nil),
	}
}

// Describe sends all metric descriptors to the channel.
func (c *Collector) Describe(ch chan<- *prometheus.Desc) {
	for _, desc := range []*prometheus.Desc{
		c.cpuSeconds,
		c.memoryTotal, c.memoryAvailable, c.memoryFree, c.memoryCached,
		c.uptime,
		c.diskReadsTotal, c.diskWritesTotal, c.diskReadBytes, c.diskWrittenBytes,
		c.netRxBytes, c.netTxBytes, c.netRxErrors, c.netTxErrors,
	} {
		ch <- desc
	}
}

// Collect reads the relevant /proc files and emits one sample per
// descriptor. Errors are logged at debug level; partial scrapes still
// produce useful output.
func (c *Collector) Collect(ch chan<- prometheus.Metric) {
	if cpu, err := ReadCPUTimes(c.procRoot); err == nil {
		emit := func(mode string, ticks uint64) {
			ch <- prometheus.MustNewConstMetric(c.cpuSeconds, prometheus.CounterValue, float64(ticks)/clockTicksPerSecond, c.hostname, mode)
		}
		emit("user", cpu.User)
		emit("nice", cpu.Nice)
		emit("system", cpu.System)
		emit("idle", cpu.Idle)
		emit("iowait", cpu.IOWait)
		emit("irq", cpu.IRQ)
		emit("softirq", cpu.SoftIRQ)
		emit("steal", cpu.Steal)
	} else {
		c.logger.Debug("read cpu", "error", err)
	}

	if mem, err := ReadMemory(c.procRoot); err == nil {
		ch <- prometheus.MustNewConstMetric(c.memoryTotal, prometheus.GaugeValue, float64(mem.TotalBytes), c.hostname)
		ch <- prometheus.MustNewConstMetric(c.memoryAvailable, prometheus.GaugeValue, float64(mem.AvailableBytes), c.hostname)
		ch <- prometheus.MustNewConstMetric(c.memoryFree, prometheus.GaugeValue, float64(mem.FreeBytes), c.hostname)
		ch <- prometheus.MustNewConstMetric(c.memoryCached, prometheus.GaugeValue, float64(mem.CachedBytes), c.hostname)
	} else {
		c.logger.Debug("read memory", "error", err)
	}

	if up, err := Uptime(c.procRoot); err == nil {
		ch <- prometheus.MustNewConstMetric(c.uptime, prometheus.GaugeValue, up, c.hostname)
	} else {
		c.logger.Debug("read uptime", "error", err)
	}

	if disks, err := ReadDiskCounters(c.procRoot); err == nil {
		for _, d := range disks {
			ch <- prometheus.MustNewConstMetric(c.diskReadsTotal, prometheus.CounterValue, float64(d.ReadsTotal), c.hostname, d.Device)
			ch <- prometheus.MustNewConstMetric(c.diskWritesTotal, prometheus.CounterValue, float64(d.WritesTotal), c.hostname, d.Device)
			ch <- prometheus.MustNewConstMetric(c.diskReadBytes, prometheus.CounterValue, float64(d.ReadBytes), c.hostname, d.Device)
			ch <- prometheus.MustNewConstMetric(c.diskWrittenBytes, prometheus.CounterValue, float64(d.WrittenBytes), c.hostname, d.Device)
		}
	} else {
		c.logger.Debug("read disks", "error", err)
	}

	if nics, err := ReadNetInterfaceCounters(c.procRoot); err == nil {
		for _, n := range nics {
			ch <- prometheus.MustNewConstMetric(c.netRxBytes, prometheus.CounterValue, float64(n.ReceivedBytes), c.hostname, n.Interface)
			ch <- prometheus.MustNewConstMetric(c.netTxBytes, prometheus.CounterValue, float64(n.TransmitBytes), c.hostname, n.Interface)
			ch <- prometheus.MustNewConstMetric(c.netRxErrors, prometheus.CounterValue, float64(n.ReceivedErrors), c.hostname, n.Interface)
			ch <- prometheus.MustNewConstMetric(c.netTxErrors, prometheus.CounterValue, float64(n.TransmitErrors), c.hostname, n.Interface)
		}
	} else {
		c.logger.Debug("read network", "error", err)
	}
}
