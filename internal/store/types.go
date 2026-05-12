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
	Duration  time.Duration
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
