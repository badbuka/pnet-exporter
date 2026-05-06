package collector

import (
	"os"
	"strconv"

	"pnet-exporter/internal/store"

	"github.com/prometheus/client_golang/prometheus"
)

var (
	nodeHostname    = detectNodeHostname()
	containerLabels = []string{"node_hostname", "container_id", "container_name", "pod_id"}
)

type NetworkCollector struct {
	store *store.Store

	tcpListen      *prometheus.Desc
	tcpSuccessful  *prometheus.Desc
	tcpFailed      *prometheus.Desc
	tcpRetransmits *prometheus.Desc
	tcpActive      *prometheus.Desc
	tcpBytesSent   *prometheus.Desc
	tcpBytesRecv   *prometheus.Desc
	latency        *prometheus.Desc
	dnsRequests    *prometheus.Desc
	dnsDuration    histogramDesc
	ipToFQDN       *prometheus.Desc
}

func NewNetworkCollector(store *store.Store) *NetworkCollector {
	endpointLabels := appendContainerLabels("destination", "actual_destination")
	return &NetworkCollector{
		store: store,
		tcpListen: prometheus.NewDesc(
			"container_net_tcp_listen_info",
			"A TCP listen address of the container.",
			appendContainerLabels("listen_addr", "proxy"),
			nil,
		),
		tcpSuccessful: prometheus.NewDesc(
			"container_net_tcp_successful_connects_total",
			"Total number of successful TCP connection attempts.",
			endpointLabels,
			nil,
		),
		tcpFailed: prometheus.NewDesc(
			"container_net_tcp_failed_connects_total",
			"Total number of failed TCP connects to a particular endpoint.",
			appendContainerLabels("destination"),
			nil,
		),
		tcpRetransmits: prometheus.NewDesc(
			"container_net_tcp_retransmits_total",
			"Total number of retransmitted TCP segments for outbound TCP connections.",
			endpointLabels,
			nil,
		),
		tcpActive: prometheus.NewDesc(
			"container_net_tcp_active_connections",
			"Number of active outbound TCP connections between the container and an endpoint.",
			endpointLabels,
			nil,
		),
		tcpBytesSent: prometheus.NewDesc(
			"container_net_tcp_bytes_sent_total",
			"Total number of bytes sent to the peer.",
			endpointLabels,
			nil,
		),
		tcpBytesRecv: prometheus.NewDesc(
			"container_net_tcp_bytes_received_total",
			"Total number of bytes received from the peer.",
			endpointLabels,
			nil,
		),
		latency: prometheus.NewDesc(
			"container_net_latency_seconds",
			"Round-trip time between the container and a remote IP.",
			appendContainerLabels("destination_ip"),
			nil,
		),
		dnsRequests: prometheus.NewDesc(
			"container_dns_requests_total",
			"Total number of outbound DNS requests.",
			appendContainerLabels("domain", "request_type", "status"),
			nil,
		),
		dnsDuration: newHistogramDesc(
			"container_dns_requests_duration_seconds",
			"Histogram of the response time for outbound DNS requests.",
			containerLabels,
		),
		ipToFQDN: prometheus.NewDesc(
			"ip_to_fqdn",
			"Mapping IP addresses to FQDNs based on DNS requests initiated by containers.",
			appendContainerLabels("ip", "fqdn"),
			nil,
		),
	}
}

func (c *NetworkCollector) Describe(ch chan<- *prometheus.Desc) {
	for _, desc := range []*prometheus.Desc{
		c.tcpListen,
		c.tcpSuccessful,
		c.tcpFailed,
		c.tcpRetransmits,
		c.tcpActive,
		c.tcpBytesSent,
		c.tcpBytesRecv,
		c.latency,
		c.dnsRequests,
		c.ipToFQDN,
		c.dnsDuration.bucket,
		c.dnsDuration.sum,
		c.dnsDuration.count,
	} {
		ch <- desc
	}
}

func (c *NetworkCollector) Collect(ch chan<- prometheus.Metric) {
	snapshot := c.store.Snapshot()
	for _, series := range snapshot.Listens {
		ch <- prometheus.MustNewConstMetric(c.tcpListen, prometheus.GaugeValue, series.Value, labelValues(series.Container, series.ListenAddr, series.Proxy)...)
	}
	for _, series := range snapshot.Successful {
		ch <- endpointMetric(c.tcpSuccessful, prometheus.CounterValue, series)
	}
	for _, series := range snapshot.Failed {
		ch <- prometheus.MustNewConstMetric(c.tcpFailed, prometheus.CounterValue, series.Value, labelValues(series.Container, series.Destination)...)
	}
	for _, series := range snapshot.Retransmits {
		ch <- endpointMetric(c.tcpRetransmits, prometheus.CounterValue, series)
	}
	for _, series := range snapshot.Active {
		ch <- endpointMetric(c.tcpActive, prometheus.GaugeValue, series)
	}
	for _, series := range snapshot.BytesSent {
		ch <- endpointMetric(c.tcpBytesSent, prometheus.CounterValue, series)
	}
	for _, series := range snapshot.BytesReceived {
		ch <- endpointMetric(c.tcpBytesRecv, prometheus.CounterValue, series)
	}
	for _, series := range snapshot.Latency {
		ch <- prometheus.MustNewConstMetric(c.latency, prometheus.GaugeValue, series.Value, labelValues(series.Container, series.DestinationIP)...)
	}
	for _, series := range snapshot.DNSRequests {
		ch <- prometheus.MustNewConstMetric(c.dnsRequests, prometheus.CounterValue, series.Value, labelValues(series.Container, series.Domain, series.RequestType, series.Status)...)
	}
	for _, series := range snapshot.DNSDurations {
		collectHistogram(ch, c.dnsDuration, series.Container, series.Buckets, series.Sum, series.Count)
	}
	for _, series := range snapshot.IPToFQDN {
		ch <- prometheus.MustNewConstMetric(c.ipToFQDN, prometheus.GaugeValue, series.Value, labelValues(series.Container, series.IP, series.FQDN)...)
	}
}

func endpointMetric(desc *prometheus.Desc, valueType prometheus.ValueType, series store.EndpointSeries) prometheus.Metric {
	return prometheus.MustNewConstMetric(desc, valueType, series.Value, labelValues(series.Container, series.Destination, series.ActualDestination)...)
}

type histogramDesc struct {
	bucket *prometheus.Desc
	sum    *prometheus.Desc
	count  *prometheus.Desc
}

func newHistogramDesc(name, help string, labels []string) histogramDesc {
	return histogramDesc{
		bucket: prometheus.NewDesc(name+"_bucket", help, append(append([]string{}, labels...), "le"), nil),
		sum:    prometheus.NewDesc(name+"_sum", help, labels, nil),
		count:  prometheus.NewDesc(name+"_count", help, labels, nil),
	}
}

func collectHistogram(ch chan<- prometheus.Metric, desc histogramDesc, labels store.ContainerLabels, buckets []store.Bucket, sum float64, count uint64, extra ...string) {
	base := labelValues(labels, extra...)
	for _, bucket := range buckets {
		ch <- prometheus.MustNewConstMetric(desc.bucket, prometheus.CounterValue, float64(bucket.Count), append(base, strconv.FormatFloat(bucket.UpperBound, 'g', -1, 64))...)
	}
	ch <- prometheus.MustNewConstMetric(desc.bucket, prometheus.CounterValue, float64(count), append(base, "+Inf")...)
	ch <- prometheus.MustNewConstMetric(desc.sum, prometheus.CounterValue, sum, base...)
	ch <- prometheus.MustNewConstMetric(desc.count, prometheus.CounterValue, float64(count), base...)
}

func appendContainerLabels(extra ...string) []string {
	labels := append([]string{}, containerLabels...)
	return append(labels, extra...)
}

func labelValues(labels store.ContainerLabels, extra ...string) []string {
	values := []string{nodeHostname, labels.ContainerID, labels.ContainerName, labels.PodID}
	return append(values, extra...)
}

func detectNodeHostname() string {
	hostname, err := os.Hostname()
	if err != nil || hostname == "" {
		return "unknown"
	}
	return hostname
}
