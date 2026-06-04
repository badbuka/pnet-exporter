package store

type listenKey struct {
	container  ContainerLabels
	listenAddr string
	proxy      string
}

type endpointKey struct {
	container         ContainerLabels
	destination       string
	actualDestination string
}

type failedKey struct {
	container   ContainerLabels
	destination string
}

type latencyKey struct {
	container     ContainerLabels
	destinationIP string
}

type dnsKey struct {
	container   ContainerLabels
	domain      string
	requestType string
	status      string
}

type dnsDurationKey struct {
	container ContainerLabels
}

type ipFQDNKey struct {
	container ContainerLabels
	ip        string
	fqdn      string
}

type protocolKey struct {
	protocol          Protocol
	container         ContainerLabels
	destination       string
	actualDestination string
	status            string
	url               string
}

type protocolDurationKey struct {
	protocol          Protocol
	container         ContainerLabels
	destination       string
	actualDestination string
	url               string
}

type oomKey struct {
	container ContainerLabels
}

type delayKey struct {
	container ContainerLabels
}

type sourceKey struct {
	container ContainerLabels
	source    string
}
