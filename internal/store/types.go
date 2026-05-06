package store

import "time"

type ContainerLabels struct {
	ContainerID   string
	ContainerName string
	PodID         string
}

func (l ContainerLabels) Values() []string {
	return []string{l.ContainerID, l.ContainerName, l.PodID}
}

type Endpoint struct {
	Destination       string
	ActualDestination string
}

type TCPEvent struct {
	Container ContainerLabels
	Endpoint  Endpoint
	Bytes     uint64
	Value     float64
}

type ListenEndpoint struct {
	Container  ContainerLabels
	ListenAddr string
	Proxy      string
	Value      float64
}

type DNSEvent struct {
	Container   ContainerLabels
	Domain      string
	RequestType string
	Status      string
	Duration    time.Duration
}

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

type ProtocolEvent struct {
	Protocol  Protocol
	Container ContainerLabels
	Endpoint  Endpoint
	Status    string
	Method    string
	Duration  time.Duration
}

type LatencySample struct {
	Container     ContainerLabels
	DestinationIP string
	Seconds       float64
}
