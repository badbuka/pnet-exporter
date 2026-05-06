package store

type Snapshot struct {
	Listens       []ListenSeries
	Successful    []EndpointSeries
	Failed        []FailedSeries
	Retransmits   []EndpointSeries
	Active        []EndpointSeries
	BytesSent     []EndpointSeries
	BytesReceived []EndpointSeries
	Latency       []LatencySeries
	DNSRequests   []DNSSeries
	DNSDurations  []DNSHistogram
	IPToFQDN      []IPFQDNSeries
	Protocol      []ProtocolSeries
	ProtocolDur   []ProtocolHistogram
}

type ListenSeries struct {
	Container  ContainerLabels
	ListenAddr string
	Proxy      string
	Value      float64
}

type EndpointSeries struct {
	Container         ContainerLabels
	Destination       string
	ActualDestination string
	Value             float64
}

type FailedSeries struct {
	Container   ContainerLabels
	Destination string
	Value       float64
}

type LatencySeries struct {
	Container     ContainerLabels
	DestinationIP string
	Value         float64
}

type DNSSeries struct {
	Container   ContainerLabels
	Domain      string
	RequestType string
	Status      string
	Value       float64
}

type DNSHistogram struct {
	Container ContainerLabels
	Buckets   []Bucket
	Sum       float64
	Count     uint64
}

type IPFQDNSeries struct {
	Container ContainerLabels
	IP        string
	FQDN      string
	Value     float64
}

type ProtocolSeries struct {
	Protocol          Protocol
	Container         ContainerLabels
	Destination       string
	ActualDestination string
	Status            string
	Method            string
	Value             float64
}

type ProtocolHistogram struct {
	Protocol          Protocol
	Container         ContainerLabels
	Destination       string
	ActualDestination string
	Buckets           []Bucket
	Sum               float64
	Count             uint64
}

type Bucket struct {
	UpperBound float64
	Count      uint64
}
