package store

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"

	"pnet-exporter/internal/config"
)

const overflowLabel = "~other"

type Store struct {
	mu sync.RWMutex

	cfg config.StoreConfig

	listens       map[listenKey]seriesValue
	successful    map[endpointKey]seriesValue
	failed        map[failedKey]seriesValue
	retransmits   map[endpointKey]seriesValue
	active        map[endpointKey]seriesValue
	bytesSent     map[endpointKey]seriesValue
	bytesReceived map[endpointKey]seriesValue
	latency       map[latencyKey]seriesValue
	dnsRequests   map[dnsKey]seriesValue
	dnsDurations  map[dnsDurationKey]histogramValue
	ipToFQDN      map[ipFQDNKey]seriesValue
	protocol      map[protocolKey]seriesValue
	protocolDur   map[protocolDurationKey]histogramValue

	destinationSeen map[string]map[string]struct{}
	fqdnSeen        map[string]map[string]struct{}
	protocolSeen    map[string]map[string]struct{}
}

func New(cfg config.StoreConfig) *Store {
	return &Store{
		cfg:             cfg,
		listens:         make(map[listenKey]seriesValue),
		successful:      make(map[endpointKey]seriesValue),
		failed:          make(map[failedKey]seriesValue),
		retransmits:     make(map[endpointKey]seriesValue),
		active:          make(map[endpointKey]seriesValue),
		bytesSent:       make(map[endpointKey]seriesValue),
		bytesReceived:   make(map[endpointKey]seriesValue),
		latency:         make(map[latencyKey]seriesValue),
		dnsRequests:     make(map[dnsKey]seriesValue),
		dnsDurations:    make(map[dnsDurationKey]histogramValue),
		ipToFQDN:        make(map[ipFQDNKey]seriesValue),
		protocol:        make(map[protocolKey]seriesValue),
		protocolDur:     make(map[protocolDurationKey]histogramValue),
		destinationSeen: make(map[string]map[string]struct{}),
		fqdnSeen:        make(map[string]map[string]struct{}),
		protocolSeen:    make(map[string]map[string]struct{}),
	}
}

func (s *Store) RunJanitor(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.Prune(time.Now())
		}
	}
}

func (s *Store) ObserveListen(event ListenEndpoint) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := listenKey{container: event.Container, listenAddr: event.ListenAddr, proxy: event.Proxy}
	s.listens[key] = seriesValue{value: event.Value, updatedAt: time.Now()}
}

func (s *Store) IncSuccessfulConnect(event TCPEvent) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := s.endpointKey(event.Container, event.Endpoint)
	s.incEndpoint(s.successful, key, 1)
}

func (s *Store) IncFailedConnect(event TCPEvent) {
	s.mu.Lock()
	defer s.mu.Unlock()
	destination := s.boundDestination(event.Container.ContainerID, event.Endpoint.Destination)
	key := failedKey{container: event.Container, destination: destination}
	s.failed[key] = seriesValue{value: s.failed[key].value + 1, updatedAt: time.Now()}
}

func (s *Store) IncRetransmit(event TCPEvent) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := s.endpointKey(event.Container, event.Endpoint)
	s.incEndpoint(s.retransmits, key, 1)
}

func (s *Store) SetActiveConnections(event TCPEvent) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := s.endpointKey(event.Container, event.Endpoint)
	s.active[key] = seriesValue{value: event.Value, updatedAt: time.Now()}
}

func (s *Store) AddBytesSent(event TCPEvent) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := s.endpointKey(event.Container, event.Endpoint)
	s.incEndpoint(s.bytesSent, key, float64(event.Bytes))
}

func (s *Store) AddBytesReceived(event TCPEvent) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := s.endpointKey(event.Container, event.Endpoint)
	s.incEndpoint(s.bytesReceived, key, float64(event.Bytes))
}

func (s *Store) SetLatency(sample LatencySample) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := latencyKey{container: sample.Container, destinationIP: sample.DestinationIP}
	s.latency[key] = seriesValue{value: sample.Seconds, updatedAt: time.Now()}
}

func (s *Store) ObserveDNS(event DNSEvent) {
	s.mu.Lock()
	defer s.mu.Unlock()
	domain := s.boundFQDN(event.Container.ContainerID, event.Domain)
	key := dnsKey{
		container:   event.Container,
		domain:      domain,
		requestType: event.RequestType,
		status:      event.Status,
	}
	s.dnsRequests[key] = seriesValue{value: s.dnsRequests[key].value + 1, updatedAt: time.Now()}

	histKey := dnsDurationKey{container: event.Container}
	hist := s.dnsDurations[histKey]
	hist.observe(event.Duration.Seconds(), s.cfg.DNSDurationBuckets)
	s.dnsDurations[histKey] = hist
}

func (s *Store) SetIPFQDN(mapping IPFQDNMapping) {
	s.mu.Lock()
	defer s.mu.Unlock()
	fqdn := s.boundFQDN(mapping.Container.ContainerID, mapping.FQDN)
	key := ipFQDNKey{container: mapping.Container, ip: mapping.IP, fqdn: fqdn}
	s.ipToFQDN[key] = seriesValue{value: mapping.Value, updatedAt: time.Now()}
}

func (s *Store) ObserveProtocol(event ProtocolEvent) {
	s.mu.Lock()
	defer s.mu.Unlock()
	endpoint := Endpoint{
		Destination:       s.boundDestination(event.Container.ContainerID, event.Endpoint.Destination),
		ActualDestination: s.boundDestination(event.Container.ContainerID, event.Endpoint.ActualDestination),
	}
	_ = s.boundProtocolKey(event.Container.ContainerID, fmt.Sprintf("%s:%s", event.Protocol, event.Method), event.Method)
	key := protocolKey{
		protocol:          event.Protocol,
		container:         event.Container,
		destination:       endpoint.Destination,
		actualDestination: endpoint.ActualDestination,
		status:            event.Status,
		method:            "",
	}
	s.protocol[key] = seriesValue{value: s.protocol[key].value + 1, updatedAt: time.Now()}

	histKey := protocolDurationKey{
		protocol:          event.Protocol,
		container:         event.Container,
		destination:       endpoint.Destination,
		actualDestination: endpoint.ActualDestination,
	}
	hist := s.protocolDur[histKey]
	hist.observe(event.Duration.Seconds(), s.cfg.DurationBuckets)
	s.protocolDur[histKey] = hist
}

func (s *Store) Snapshot() Snapshot {
	s.mu.RLock()
	defer s.mu.RUnlock()

	snapshot := Snapshot{
		Listens:       make([]ListenSeries, 0, len(s.listens)),
		Successful:    make([]EndpointSeries, 0, len(s.successful)),
		Failed:        make([]FailedSeries, 0, len(s.failed)),
		Retransmits:   make([]EndpointSeries, 0, len(s.retransmits)),
		Active:        make([]EndpointSeries, 0, len(s.active)),
		BytesSent:     make([]EndpointSeries, 0, len(s.bytesSent)),
		BytesReceived: make([]EndpointSeries, 0, len(s.bytesReceived)),
		Latency:       make([]LatencySeries, 0, len(s.latency)),
		DNSRequests:   make([]DNSSeries, 0, len(s.dnsRequests)),
		DNSDurations:  make([]DNSHistogram, 0, len(s.dnsDurations)),
		IPToFQDN:      make([]IPFQDNSeries, 0, len(s.ipToFQDN)),
		Protocol:      make([]ProtocolSeries, 0, len(s.protocol)),
		ProtocolDur:   make([]ProtocolHistogram, 0, len(s.protocolDur)),
	}
	for key, value := range s.listens {
		snapshot.Listens = append(snapshot.Listens, ListenSeries{Container: key.container, ListenAddr: key.listenAddr, Proxy: key.proxy, Value: value.value})
	}
	for key, value := range s.successful {
		snapshot.Successful = append(snapshot.Successful, endpointSeries(key, value))
	}
	for key, value := range s.failed {
		snapshot.Failed = append(snapshot.Failed, FailedSeries{Container: key.container, Destination: key.destination, Value: value.value})
	}
	for key, value := range s.retransmits {
		snapshot.Retransmits = append(snapshot.Retransmits, endpointSeries(key, value))
	}
	for key, value := range s.active {
		snapshot.Active = append(snapshot.Active, endpointSeries(key, value))
	}
	for key, value := range s.bytesSent {
		snapshot.BytesSent = append(snapshot.BytesSent, endpointSeries(key, value))
	}
	for key, value := range s.bytesReceived {
		snapshot.BytesReceived = append(snapshot.BytesReceived, endpointSeries(key, value))
	}
	for key, value := range s.latency {
		snapshot.Latency = append(snapshot.Latency, LatencySeries{Container: key.container, DestinationIP: key.destinationIP, Value: value.value})
	}
	for key, value := range s.dnsRequests {
		snapshot.DNSRequests = append(snapshot.DNSRequests, DNSSeries{Container: key.container, Domain: key.domain, RequestType: key.requestType, Status: key.status, Value: value.value})
	}
	for key, value := range s.dnsDurations {
		snapshot.DNSDurations = append(snapshot.DNSDurations, DNSHistogram{Container: key.container, Buckets: value.SortedBuckets(), Sum: value.sum, Count: value.count})
	}
	for key, value := range s.ipToFQDN {
		snapshot.IPToFQDN = append(snapshot.IPToFQDN, IPFQDNSeries{Container: key.container, IP: key.ip, FQDN: key.fqdn, Value: value.value})
	}
	for key, value := range s.protocol {
		snapshot.Protocol = append(snapshot.Protocol, ProtocolSeries{
			Protocol:          key.protocol,
			Container:         key.container,
			Destination:       key.destination,
			ActualDestination: key.actualDestination,
			Status:            key.status,
			Method:            key.method,
			Value:             value.value,
		})
	}
	for key, value := range s.protocolDur {
		snapshot.ProtocolDur = append(snapshot.ProtocolDur, ProtocolHistogram{
			Protocol:          key.protocol,
			Container:         key.container,
			Destination:       key.destination,
			ActualDestination: key.actualDestination,
			Buckets:           value.SortedBuckets(),
			Sum:               value.sum,
			Count:             value.count,
		})
	}
	return snapshot
}

func (s *Store) Prune(now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()

	pruneSeries(s.listens, now, s.cfg.MetricTTL)
	pruneSeries(s.successful, now, s.cfg.MetricTTL)
	pruneSeries(s.failed, now, s.cfg.MetricTTL)
	pruneSeries(s.retransmits, now, s.cfg.MetricTTL)
	pruneSeries(s.active, now, s.cfg.MetricTTL)
	pruneSeries(s.bytesSent, now, s.cfg.MetricTTL)
	pruneSeries(s.bytesReceived, now, s.cfg.MetricTTL)
	pruneSeries(s.latency, now, s.cfg.MetricTTL)
	pruneSeries(s.dnsRequests, now, s.cfg.MetricTTL)
	pruneSeries(s.ipToFQDN, now, s.cfg.MetricTTL)
	pruneSeries(s.protocol, now, s.cfg.MetricTTL)
	pruneHistograms(s.dnsDurations, now, s.cfg.MetricTTL)
	pruneHistograms(s.protocolDur, now, s.cfg.MetricTTL)
}

func (s *Store) incEndpoint(values map[endpointKey]seriesValue, key endpointKey, delta float64) {
	values[key] = seriesValue{value: values[key].value + delta, updatedAt: time.Now()}
}

func (s *Store) endpointKey(container ContainerLabels, endpoint Endpoint) endpointKey {
	actualDestination := endpoint.ActualDestination
	if actualDestination == "" {
		actualDestination = endpoint.Destination
	}
	return endpointKey{
		container:         container,
		destination:       s.boundDestination(container.ContainerID, endpoint.Destination),
		actualDestination: s.boundDestination(container.ContainerID, actualDestination),
	}
}

func (s *Store) boundDestination(containerID, destination string) string {
	return s.boundValue(s.destinationSeen, containerID, destination, s.cfg.DestinationLimit)
}

func (s *Store) boundFQDN(containerID, fqdn string) string {
	return s.boundValue(s.fqdnSeen, containerID, fqdn, s.cfg.FQDNCeiling)
}

func (s *Store) boundProtocolKey(containerID, unique, value string) string {
	if s.boundValue(s.protocolSeen, containerID, unique, s.cfg.ProtocolKeyLimit) == overflowLabel {
		return overflowLabel
	}
	return value
}

func (s *Store) boundValue(seen map[string]map[string]struct{}, containerID, value string, limit int) string {
	if value == "" {
		return ""
	}
	if seen[containerID] == nil {
		seen[containerID] = make(map[string]struct{})
	}
	if _, ok := seen[containerID][value]; ok {
		return value
	}
	if len(seen[containerID]) >= limit {
		return overflowLabel
	}
	seen[containerID][value] = struct{}{}
	return value
}

type seriesValue struct {
	value     float64
	updatedAt time.Time
}

type histogramValue struct {
	buckets   map[float64]uint64
	sum       float64
	count     uint64
	updatedAt time.Time
}

func (h *histogramValue) observe(value float64, buckets []float64) {
	if h.buckets == nil {
		h.buckets = make(map[float64]uint64, len(buckets))
	}
	for _, bucket := range buckets {
		if _, ok := h.buckets[bucket]; !ok {
			h.buckets[bucket] = 0
		}
		if value <= bucket {
			h.buckets[bucket]++
		}
	}
	h.sum += value
	h.count++
	h.updatedAt = time.Now()
}

func (h histogramValue) SortedBuckets() []Bucket {
	bounds := make([]float64, 0, len(h.buckets))
	for bound := range h.buckets {
		bounds = append(bounds, bound)
	}
	sort.Float64s(bounds)

	buckets := make([]Bucket, 0, len(bounds))
	for _, bound := range bounds {
		buckets = append(buckets, Bucket{UpperBound: bound, Count: h.buckets[bound]})
	}
	return buckets
}

func pruneSeries[K comparable](values map[K]seriesValue, now time.Time, ttl time.Duration) {
	for key, value := range values {
		if now.Sub(value.updatedAt) > ttl {
			delete(values, key)
		}
	}
}

func pruneHistograms[K comparable](values map[K]histogramValue, now time.Time, ttl time.Duration) {
	for key, value := range values {
		if now.Sub(value.updatedAt) > ttl {
			delete(values, key)
		}
	}
}

func endpointSeries(key endpointKey, value seriesValue) EndpointSeries {
	return EndpointSeries{
		Container:         key.container,
		Destination:       key.destination,
		ActualDestination: key.actualDestination,
		Value:             value.value,
	}
}
