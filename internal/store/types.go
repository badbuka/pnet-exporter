package store

import "time"

// ContainerLabels holds the Prometheus label values attached to every metric series for a single container.
type ContainerLabels struct {
	ContainerID   string
	ContainerName string
	PodID         string
}

func (l ContainerLabels) Values() []string {
	return []string{l.ContainerID, l.ContainerName, l.PodID}
}

// Endpoint describes a TCP destination, optionally including the post-NAT actual destination.
type Endpoint struct {
	Destination       string
	ActualDestination string
}

// TCPEvent carries a single TCP lifecycle event (connect, close, bytes, etc.) from the BPF layer to the store.
type TCPEvent struct {
	Container ContainerLabels
	Endpoint  Endpoint
	Bytes     uint64
	Value     float64
}

// InboundEvent carries a single inbound (server-side) TCP event from the
// BPF layer to the store. Source is the remote client endpoint (IP:port).
type InboundEvent struct {
	Container ContainerLabels
	Source    string
	Bytes     uint64
	Value     float64
}

// ListenEndpoint describes a TCP address that a container is actively listening on.
type ListenEndpoint struct {
	Container  ContainerLabels
	ListenAddr string
	Proxy      string
	Value      float64
}

// DNSEvent carries a single DNS request/response observation from the BPF layer to the store.
type DNSEvent struct {
	Container   ContainerLabels
	Domain      string
	RequestType string
	Status      string
	Duration    time.Duration
}

// IPFQDNMapping records that a given IP address resolved to the named FQDN within a container.
type IPFQDNMapping struct {
	Container ContainerLabels
	IP        string
	FQDN      string
	Value     float64
}

type Protocol string

const (
	ProtocolHTTP     Protocol = "http"
	ProtocolPostgres Protocol = "postgres"
	ProtocolRedis    Protocol = "redis"
	ProtocolKafka    Protocol = "kafka"
)

// ProtocolEvent carries a single application-protocol request observation (HTTP, Postgres, Redis, Kafka) from the BPF layer to the store.
type ProtocolEvent struct {
	Protocol  Protocol
	Container ContainerLabels
	Endpoint  Endpoint
	Status    string
	// URL is the full request URL (host+path) for HTTP requests; empty for
	// other protocols and for HTTP requests whose URL could not be parsed.
	URL      string
	Duration time.Duration
}

type LatencySample struct {
	Container     ContainerLabels
	DestinationIP string
	Seconds       float64
}

// OOMEvent is recorded whenever the kernel OOM killer fires inside a
// known container.
type OOMEvent struct {
	Container ContainerLabels
	VictimPID uint32
}

// ResourceDelaySample is the per-container delay-accounting reading
// (cpu / disk wait time) aggregated from taskstats.
type ResourceDelaySample struct {
	Container       ContainerLabels
	CPUDelaySeconds float64
	IODelaySeconds  float64
}

// ResourceUsageSample is a per-container resource-utilization reading
// collected from the cgroup v2 control files (cpu.stat, memory.*,
// io.stat, *.pressure). Counter fields hold cumulative kernel totals;
// gauge fields (memory.*) hold the instantaneous value. The Has* flags
// mark optional readings whose source file may be absent on a given host
// so the collector can skip emitting an unset series.
type ResourceUsageSample struct {
	Container ContainerLabels

	// cpu.stat (counters, seconds / counts)
	CPUUsageSeconds     float64
	CPUUserSeconds      float64
	CPUSystemSeconds    float64
	CPUPeriods          float64
	CPUThrottledPeriods float64
	CPUThrottledSeconds float64

	// memory.* (gauges, bytes)
	MemoryUsageBytes float64
	MemoryPeakBytes  float64
	MemoryLimitBytes float64
	HasMemoryPeak    bool
	HasMemoryLimit   bool

	// io.stat (counters, summed across devices)
	IOReadBytes    float64
	IOWrittenBytes float64
	IOReads        float64
	IOWrites       float64

	// PSI pressure totals (counters, seconds)
	CPUPressureSomeSeconds    float64
	CPUPressureFullSeconds    float64
	MemoryPressureSomeSeconds float64
	MemoryPressureFullSeconds float64
	IOPressureSomeSeconds     float64
	IOPressureFullSeconds     float64
	HasCPUPressure            bool
	HasMemoryPressure         bool
	HasIOPressure             bool
}
