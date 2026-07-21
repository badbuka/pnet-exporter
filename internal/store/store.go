package store

import (
	"context"
	"net"
	"sort"
	"strconv"
	"sync"
	"time"

	"pnet-exporter/internal/config"
)

const overflowLabel = "~other"

// dynamicPortLabel replaces the port of an address whose port falls in the
// configured dynamic/ephemeral range. Collapsing these ports keeps all
// short-lived connections to a host in a single time series instead of one
// per connection.
const dynamicPortLabel = "dyn_ports"

// Store holds all metric series in memory between Prometheus scrapes.
//
// Series are partitioned into two TTL classes:
//
//   - Counters and listen-state gauges keep their last published value
//     forever (or until the container is forgotten). This preserves counter
//     monotonicity across idle periods, since Prometheus interprets a value
//     decrease as a counter reset.
//   - Stateful samples (active connections, latency, IP→FQDN mappings,
//     histograms) age out via MetricTTL because they describe a momentary
//     condition rather than an accumulating count.
//
// Container-keyed cardinality bookkeeping (the *Seen maps) is dropped when
// a container ID is forgotten via ForgetContainer, called by the janitor
// after consulting the identity cache.
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
	oomKills      map[oomKey]seriesValue
	delays        map[delayKey]delayValue
	resourceUsage map[delayKey]resourceUsageValue

	inboundAccepts       map[sourceKey]seriesValue
	inboundActive        map[sourceKey]seriesValue
	inboundBytesSent     map[sourceKey]seriesValue
	inboundBytesReceived map[sourceKey]seriesValue

	destinationSeen map[string]map[string]struct{}
	fqdnSeen        map[string]map[string]struct{}
	urlSeen         map[string]map[string]struct{}
	sourceSeen      map[string]map[string]struct{}
	ipSeen          map[string]map[string]struct{}
}

func New(cfg config.StoreConfig) *Store {
	return &Store{
		cfg:           cfg,
		listens:       make(map[listenKey]seriesValue),
		successful:    make(map[endpointKey]seriesValue),
		failed:        make(map[failedKey]seriesValue),
		retransmits:   make(map[endpointKey]seriesValue),
		active:        make(map[endpointKey]seriesValue),
		bytesSent:     make(map[endpointKey]seriesValue),
		bytesReceived: make(map[endpointKey]seriesValue),
		latency:       make(map[latencyKey]seriesValue),
		dnsRequests:   make(map[dnsKey]seriesValue),
		dnsDurations:  make(map[dnsDurationKey]histogramValue),
		ipToFQDN:      make(map[ipFQDNKey]seriesValue),
		protocol:      make(map[protocolKey]seriesValue),
		protocolDur:   make(map[protocolDurationKey]histogramValue),
		oomKills:      make(map[oomKey]seriesValue),
		delays:        make(map[delayKey]delayValue),
		resourceUsage: make(map[delayKey]resourceUsageValue),

		inboundAccepts:       make(map[sourceKey]seriesValue),
		inboundActive:        make(map[sourceKey]seriesValue),
		inboundBytesSent:     make(map[sourceKey]seriesValue),
		inboundBytesReceived: make(map[sourceKey]seriesValue),

		destinationSeen: make(map[string]map[string]struct{}),
		fqdnSeen:        make(map[string]map[string]struct{}),
		urlSeen:         make(map[string]map[string]struct{}),
		sourceSeen:      make(map[string]map[string]struct{}),
		ipSeen:          make(map[string]map[string]struct{}),
	}
}

// LiveContainersFunc returns the set of container IDs currently known to
// the identity cache. The janitor uses it to drop bookkeeping for
// containers that have disappeared.
type LiveContainersFunc func() map[string]struct{}

// RunJanitor prunes momentary metric series and per-container bookkeeping
// for containers no longer present in liveContainers.
func (s *Store) RunJanitor(ctx context.Context, interval time.Duration, liveContainers LiveContainersFunc) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.Prune(time.Now(), liveContainers)
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

// IncActiveConnection bumps the active-connection gauge for the
// container/endpoint pair. SuccessfulConnect events drive this from BPF
// tracepoints.
func (s *Store) IncActiveConnection(event TCPEvent) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := s.endpointKey(event.Container, event.Endpoint)
	v := s.active[key]
	v.value++
	v.updatedAt = time.Now()
	s.active[key] = v
}

// DecActiveConnection clamps to zero so spurious close events (e.g. a
// close observed before the matching open has been processed) cannot
// produce a negative gauge.
func (s *Store) DecActiveConnection(event TCPEvent) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := s.endpointKey(event.Container, event.Endpoint)
	v := s.active[key]
	if v.value > 0 {
		v.value--
	}
	v.updatedAt = time.Now()
	s.active[key] = v
}

// SetActiveConnections directly overwrites the gauge value. Useful for
// /proc-derived reconciliation that periodically reports an authoritative
// count.
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

	if event.Duration > 0 {
		histKey := dnsDurationKey{container: event.Container}
		hist := s.dnsDurations[histKey]
		hist.observe(event.Duration.Seconds(), s.cfg.DNSDurationBuckets)
		s.dnsDurations[histKey] = hist
	}
}

func (s *Store) SetIPFQDN(mapping IPFQDNMapping) {
	s.mu.Lock()
	defer s.mu.Unlock()
	fqdn := s.boundFQDN(mapping.Container.ContainerID, mapping.FQDN)
	// Answer IPs come from remote DNS servers and are unbounded without a
	// ceiling; reuse the destination budget since both are remote peers.
	ip := s.boundValue(s.ipSeen, mapping.Container.ContainerID, mapping.IP, s.cfg.DestinationLimit)
	key := ipFQDNKey{container: mapping.Container, ip: ip, fqdn: fqdn}
	s.ipToFQDN[key] = seriesValue{value: mapping.Value, updatedAt: time.Now()}
}

func (s *Store) ObserveProtocol(event ProtocolEvent) {
	s.mu.Lock()
	defer s.mu.Unlock()
	endpoint := Endpoint{
		Destination:       s.boundDestination(event.Container.ContainerID, event.Endpoint.Destination),
		ActualDestination: s.boundDestination(event.Container.ContainerID, event.Endpoint.ActualDestination),
	}
	url := s.boundURL(event.Container.ContainerID, event.URL)
	key := protocolKey{
		protocol:          event.Protocol,
		container:         event.Container,
		destination:       endpoint.Destination,
		actualDestination: endpoint.ActualDestination,
		status:            event.Status,
		url:               url,
	}
	s.protocol[key] = seriesValue{value: s.protocol[key].value + 1, updatedAt: time.Now()}

	if event.Duration > 0 {
		histKey := protocolDurationKey{
			protocol:          event.Protocol,
			container:         event.Container,
			destination:       endpoint.Destination,
			actualDestination: endpoint.ActualDestination,
			url:               url,
		}
		hist := s.protocolDur[histKey]
		hist.observe(event.Duration.Seconds(), s.cfg.DurationBuckets)
		s.protocolDur[histKey] = hist
	}
}

// ObserveOOMKill increments the OOM-kill counter for the container the
// victim PID belonged to.
func (s *Store) ObserveOOMKill(event OOMEvent) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := oomKey{container: event.Container}
	v := s.oomKills[key]
	v.value++
	v.updatedAt = time.Now()
	s.oomKills[key] = v
}

// RecordResourceDelay stores the latest cumulative delay-accounting
// counters for a container. Counters are monotonic so callers must pass
// the kernel's running totals (in seconds).
func (s *Store) RecordResourceDelay(sample ResourceDelaySample) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := delayKey{container: sample.Container}
	s.delays[key] = delayValue{
		cpu:       sample.CPUDelaySeconds,
		io:        sample.IODelaySeconds,
		updatedAt: time.Now(),
	}
}

// RecordResourceUsage stores the latest cgroup v2 resource-utilization
// reading for a container. Counter fields must be the kernel's running
// totals; gauge fields are the instantaneous value at sample time.
func (s *Store) RecordResourceUsage(sample ResourceUsageSample) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := delayKey{container: sample.Container}
	s.resourceUsage[key] = resourceUsageValue{sample: sample, updatedAt: time.Now()}
}

// IncInboundAccept increments the inbound accept counter for the
// container/source pair.
func (s *Store) IncInboundAccept(event InboundEvent) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := s.sourceKey(event.Container, event.Source)
	s.incSource(s.inboundAccepts, key, 1)
}

// IncInboundActive bumps the inbound active-connection gauge.
func (s *Store) IncInboundActive(event InboundEvent) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := s.sourceKey(event.Container, event.Source)
	v := s.inboundActive[key]
	v.value++
	v.updatedAt = time.Now()
	s.inboundActive[key] = v
}

// DecInboundActive clamps to zero so a close observed before its matching
// accept cannot drive the gauge negative.
func (s *Store) DecInboundActive(event InboundEvent) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := s.sourceKey(event.Container, event.Source)
	v := s.inboundActive[key]
	if v.value > 0 {
		v.value--
	}
	v.updatedAt = time.Now()
	s.inboundActive[key] = v
}

func (s *Store) AddInboundBytesSent(event InboundEvent) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := s.sourceKey(event.Container, event.Source)
	s.incSource(s.inboundBytesSent, key, float64(event.Bytes))
}

func (s *Store) AddInboundBytesReceived(event InboundEvent) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := s.sourceKey(event.Container, event.Source)
	s.incSource(s.inboundBytesReceived, key, float64(event.Bytes))
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
		OOMKills:      make([]OOMSeries, 0, len(s.oomKills)),
		Delays:        make([]DelaySeries, 0, len(s.delays)),

		InboundAccepts:       make([]SourceSeries, 0, len(s.inboundAccepts)),
		InboundActive:        make([]SourceSeries, 0, len(s.inboundActive)),
		InboundBytesSent:     make([]SourceSeries, 0, len(s.inboundBytesSent)),
		InboundBytesReceived: make([]SourceSeries, 0, len(s.inboundBytesReceived)),

		ResourceUsage: make([]ResourceUsageSample, 0, len(s.resourceUsage)),
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
			URL:               key.url,
			Value:             value.value,
		})
	}
	for key, value := range s.protocolDur {
		snapshot.ProtocolDur = append(snapshot.ProtocolDur, ProtocolHistogram{
			Protocol:          key.protocol,
			Container:         key.container,
			Destination:       key.destination,
			ActualDestination: key.actualDestination,
			URL:               key.url,
			Buckets:           value.SortedBuckets(),
			Sum:               value.sum,
			Count:             value.count,
		})
	}
	for key, value := range s.oomKills {
		snapshot.OOMKills = append(snapshot.OOMKills, OOMSeries{Container: key.container, Value: value.value})
	}
	for key, value := range s.delays {
		snapshot.Delays = append(snapshot.Delays, DelaySeries{
			Container:       key.container,
			CPUDelaySeconds: value.cpu,
			IODelaySeconds:  value.io,
		})
	}
	for key, value := range s.inboundAccepts {
		snapshot.InboundAccepts = append(snapshot.InboundAccepts, sourceSeries(key, value))
	}
	for key, value := range s.inboundActive {
		snapshot.InboundActive = append(snapshot.InboundActive, sourceSeries(key, value))
	}
	for key, value := range s.inboundBytesSent {
		snapshot.InboundBytesSent = append(snapshot.InboundBytesSent, sourceSeries(key, value))
	}
	for key, value := range s.inboundBytesReceived {
		snapshot.InboundBytesReceived = append(snapshot.InboundBytesReceived, sourceSeries(key, value))
	}
	for _, value := range s.resourceUsage {
		snapshot.ResourceUsage = append(snapshot.ResourceUsage, value.sample)
	}
	return snapshot
}

// Prune drops momentary samples older than MetricTTL and forgets
// per-container bookkeeping for containers that liveContainers no longer
// reports. Counter series are kept so Prometheus does not perceive their
// disappearance as a counter reset.
func (s *Store) Prune(now time.Time, liveContainers LiveContainersFunc) {
	s.mu.Lock()
	defer s.mu.Unlock()

	pruneSeries(s.active, now, s.cfg.MetricTTL)
	pruneSeries(s.inboundActive, now, s.cfg.MetricTTL)
	pruneSeries(s.latency, now, s.cfg.MetricTTL)
	pruneSeries(s.ipToFQDN, now, s.cfg.MetricTTL)
	pruneDelays(s.delays, now, s.cfg.MetricTTL)
	pruneResourceUsage(s.resourceUsage, now, s.cfg.MetricTTL)
	pruneHistograms(s.dnsDurations, now, s.cfg.MetricTTL)
	pruneHistograms(s.protocolDur, now, s.cfg.MetricTTL)

	if liveContainers == nil {
		return
	}
	live := liveContainers()
	if live == nil {
		return
	}

	dropContainer := func(id string) bool {
		_, ok := live[id]
		return !ok
	}

	for k := range s.listens {
		if dropContainer(k.container.ContainerID) {
			delete(s.listens, k)
		}
	}
	for k := range s.successful {
		if dropContainer(k.container.ContainerID) {
			delete(s.successful, k)
		}
	}
	for k := range s.failed {
		if dropContainer(k.container.ContainerID) {
			delete(s.failed, k)
		}
	}
	for k := range s.retransmits {
		if dropContainer(k.container.ContainerID) {
			delete(s.retransmits, k)
		}
	}
	for k := range s.bytesSent {
		if dropContainer(k.container.ContainerID) {
			delete(s.bytesSent, k)
		}
	}
	for k := range s.bytesReceived {
		if dropContainer(k.container.ContainerID) {
			delete(s.bytesReceived, k)
		}
	}
	for k := range s.dnsRequests {
		if dropContainer(k.container.ContainerID) {
			delete(s.dnsRequests, k)
		}
	}
	for k := range s.protocol {
		if dropContainer(k.container.ContainerID) {
			delete(s.protocol, k)
		}
	}
	for k := range s.oomKills {
		if dropContainer(k.container.ContainerID) {
			delete(s.oomKills, k)
		}
	}
	for k := range s.inboundAccepts {
		if dropContainer(k.container.ContainerID) {
			delete(s.inboundAccepts, k)
		}
	}
	for k := range s.inboundBytesSent {
		if dropContainer(k.container.ContainerID) {
			delete(s.inboundBytesSent, k)
		}
	}
	for k := range s.inboundBytesReceived {
		if dropContainer(k.container.ContainerID) {
			delete(s.inboundBytesReceived, k)
		}
	}
	for id := range s.destinationSeen {
		if dropContainer(id) {
			delete(s.destinationSeen, id)
		}
	}
	for id := range s.fqdnSeen {
		if dropContainer(id) {
			delete(s.fqdnSeen, id)
		}
	}
	for id := range s.urlSeen {
		if dropContainer(id) {
			delete(s.urlSeen, id)
		}
	}
	for id := range s.sourceSeen {
		if dropContainer(id) {
			delete(s.sourceSeen, id)
		}
	}
	for id := range s.ipSeen {
		if dropContainer(id) {
			delete(s.ipSeen, id)
		}
	}
}

func (s *Store) incEndpoint(values map[endpointKey]seriesValue, key endpointKey, delta float64) {
	values[key] = seriesValue{value: values[key].value + delta, updatedAt: time.Now()}
}

func (s *Store) incSource(values map[sourceKey]seriesValue, key sourceKey, delta float64) {
	values[key] = seriesValue{value: values[key].value + delta, updatedAt: time.Now()}
}

func (s *Store) sourceKey(container ContainerLabels, source string) sourceKey {
	return sourceKey{
		container: container,
		source:    s.boundSource(container.ContainerID, source),
	}
}

func (s *Store) boundSource(containerID, source string) string {
	return s.boundValue(s.sourceSeen, containerID, s.normalizeAddr(source), s.cfg.DestinationLimit)
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
	return s.boundValue(s.destinationSeen, containerID, s.normalizeAddr(destination), s.cfg.DestinationLimit)
}

// normalizeAddr collapses the port of an "IP:port" address into the
// dynamicPortLabel token when the port falls inside the configured
// dynamic/ephemeral range. The host is preserved so distinct hosts stay
// separate. Addresses without a parseable port (plain IPs, FQDNs) are
// returned unchanged, as is everything when the feature is disabled.
func (s *Store) normalizeAddr(addr string) string {
	if !s.cfg.CollapseDynamicPorts || addr == "" {
		return addr
	}
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return addr
	}
	if uint16(port) < s.cfg.DynamicPortMin || uint16(port) > s.cfg.DynamicPortMax {
		return addr
	}
	return net.JoinHostPort(host, dynamicPortLabel)
}

func (s *Store) boundFQDN(containerID, fqdn string) string {
	return s.boundValue(s.fqdnSeen, containerID, fqdn, s.cfg.FQDNCeiling)
}

func (s *Store) boundURL(containerID, url string) string {
	return s.boundValue(s.urlSeen, containerID, url, s.cfg.URLLimit)
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

type delayValue struct {
	cpu       float64
	io        float64
	updatedAt time.Time
}

type resourceUsageValue struct {
	sample    ResourceUsageSample
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

func pruneDelays[K comparable](values map[K]delayValue, now time.Time, ttl time.Duration) {
	for key, value := range values {
		if now.Sub(value.updatedAt) > ttl {
			delete(values, key)
		}
	}
}

func pruneResourceUsage[K comparable](values map[K]resourceUsageValue, now time.Time, ttl time.Duration) {
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

func sourceSeries(key sourceKey, value seriesValue) SourceSeries {
	return SourceSeries{
		Container: key.container,
		Source:    key.source,
		Value:     value.value,
	}
}
