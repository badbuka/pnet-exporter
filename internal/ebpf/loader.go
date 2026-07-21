package ebpf

import (
	"context"
	"log/slog"
	"net/netip"
	"sync/atomic"
	"time"

	"pnet-exporter/internal/config"
	"pnet-exporter/internal/identity"
	"pnet-exporter/internal/protocol"
	"pnet-exporter/internal/store"
)

// dnsStatsInterval controls how often the loader emits an aggregated
// "dns pipeline stats" log. Exposed as a variable so tests (and a
// possible future config knob) can override it.
var dnsStatsInterval = time.Minute

// attachKind identifies how a BPF program is attached to the kernel.
type attachKind int

const (
	attachTracepoint attachKind = iota
	attachKprobe
	attachKretprobe
)

// programDescriptor describes one compiled BPF object: the file name, the
// program name inside it, and the kernel attachment point.
type programDescriptor struct {
	Object string
	// Programs lists the (Program, AttachKind, Target) tuples to attach
	// from this object. Object files may contain several programs that
	// share a ringbuf and need to be loaded together.
	Programs []programAttachment
}

type programAttachment struct {
	Program string
	Kind    attachKind
	// Target is either "group/name" for tracepoints or the kernel
	// symbol name for kprobes/kretprobes.
	Target string
}

// programs is the canonical list of BPF programs the loader ships.
//
// New programs added here must:
//  1. live in bpf/<Object>.c, building to <Object>.o,
//  2. expose a function with `SEC("tracepoint/<group>/<name>")`,
//     `SEC("kprobe/<symbol>")`, or `SEC("kretprobe/<symbol>")`,
//  3. push events through the shared `events` ring buffer.
var programs = []programDescriptor{
	{
		Object: "tcp_state.bpf.o",
		Programs: []programAttachment{
			{Program: "handle_inet_sock_set_state", Kind: attachTracepoint, Target: "sock/inet_sock_set_state"},
		},
	},
	{
		Object: "tcp_retransmit.bpf.o",
		Programs: []programAttachment{
			{Program: "handle_tcp_retransmit_skb", Kind: attachTracepoint, Target: "tcp/tcp_retransmit_skb"},
		},
	},
	{
		Object: "tcp_bytes.bpf.o",
		Programs: []programAttachment{
			{Program: "handle_tcp_sendmsg", Kind: attachKprobe, Target: "tcp_sendmsg"},
			{Program: "handle_tcp_cleanup_rbuf", Kind: attachKprobe, Target: "tcp_cleanup_rbuf"},
		},
	},
	{
		Object: "tcp_inbound.bpf.o",
		Programs: []programAttachment{
			{Program: "handle_inet_csk_accept", Kind: attachKretprobe, Target: "inet_csk_accept"},
			{Program: "handle_inbound_sendmsg", Kind: attachKprobe, Target: "tcp_sendmsg"},
			{Program: "handle_inbound_cleanup_rbuf", Kind: attachKprobe, Target: "tcp_cleanup_rbuf"},
			{Program: "handle_inbound_close", Kind: attachKprobe, Target: "tcp_close"},
		},
	},
	{
		Object: "tcp_conntrack.bpf.o",
		Programs: []programAttachment{
			{Program: "handle_conntrack_confirm", Kind: attachKprobe, Target: "__nf_conntrack_confirm"},
		},
	},
	{
		Object: "l7.bpf.o",
		Programs: []programAttachment{
			{Program: "l7_tcp_sendmsg", Kind: attachKprobe, Target: "tcp_sendmsg"},
			{Program: "l7_tcp_recvmsg_entry", Kind: attachKprobe, Target: "tcp_recvmsg"},
			{Program: "l7_tcp_recvmsg", Kind: attachKretprobe, Target: "tcp_recvmsg"},
		},
	},
	{
		Object: "dns.bpf.o",
		Programs: []programAttachment{
			{Program: "dns_udp_sendmsg", Kind: attachKprobe, Target: "udp_sendmsg"},
			{Program: "dns_udp_recvmsg_entry", Kind: attachKprobe, Target: "udp_recvmsg"},
			{Program: "dns_udp_recvmsg", Kind: attachKretprobe, Target: "udp_recvmsg"},
		},
	},
	{
		Object: "oom.bpf.o",
		Programs: []programAttachment{
			{Program: "handle_oom_kill_process", Kind: attachKprobe, Target: "oom_kill_process"},
		},
	},
}

// Loader manages the lifecycle of all BPF programs, attached links, and
// the ring-buffer reader that consumes their events. The actual kernel
// interactions live in platform-specific files (loader_linux.go); on other
// platforms only a stub implementation is provided so the rest of the
// project can be built and unit-tested.
type Loader struct {
	cfg      config.EBPFConfig
	identity *identity.Cache
	store    *store.Store
	logger   *slog.Logger
	nat      *ttlCache[string, string]

	classifier protocol.Classifier
	tracker    *protocol.RequestTracker
	flows      *ttlCache[SocketTuple, store.Protocol]
	urls       *ttlCache[urlFlowKey, string]

	// dropIPv6, when true, discards every IPv6-bearing metric before it
	// reaches the store (IPv6 connection tuples, IPv6 DNS transport, and
	// AAAA ip_to_fqdn mappings).
	dropIPv6 bool

	dnsStats dnsPipelineStats

	state loaderState
}

// dnsPipelineStats tracks the lifecycle of DNS ringbuf events from the
// kernel through the store. Each counter is reset on every aggregate log
// flush so the values represent activity within the most recent window.
type dnsPipelineStats struct {
	recordsReceived  atomic.Uint64
	nonResponse      atomic.Uint64
	containerMissing atomic.Uint64
	parseFailed      atomic.Uint64
	noQuestions      atomic.Uint64
	requestsObserved atomic.Uint64
	mappingsObserved atomic.Uint64
}

func NewLoader(cfg config.EBPFConfig, classifier protocol.Classifier, identity *identity.Cache, metricStore *store.Store, logger *slog.Logger, dropIPv6 bool) *Loader {
	return &Loader{
		cfg:        cfg,
		identity:   identity,
		store:      metricStore,
		logger:     logger,
		nat:        newTTLCache[string, string](5 * time.Minute),
		classifier: classifier,
		tracker:    protocol.NewRequestTracker(30 * time.Second),
		flows:      newTTLCache[SocketTuple, store.Protocol](5 * time.Minute),
		urls:       newTTLCache[urlFlowKey, string](30 * time.Second),
		dropIPv6:   dropIPv6,
	}
}

// urlFlowKey identifies an in-flight request flow for associating a parsed
// request URL (only available on the request) with the later response, where
// the metric is actually emitted. It mirrors the destination fields of
// protocol.RequestKey but omits the correlation token, which differs between
// the HTTP request and response payloads.
type urlFlowKey struct {
	containerID       string
	destination       string
	actualDestination string
}

// actualDestination resolves the post-DNAT destination for dst, falling back
// to dst itself when no conntrack mapping is known.
func (l *Loader) actualDestination(dst string) string {
	if actual, ok := l.nat.get(dst); ok {
		return actual
	}
	return dst
}

func (l *Loader) dispatchTCP(event TCPEvent) {
	if l.dropIPv6 && event.Tuple.IsIPv6() {
		return
	}
	container := l.resolveContainer(event.CgroupID, event.PID)
	dst := event.Tuple.Destination()
	actual := l.actualDestination(dst)
	storeEvent := event.ToStoreEvent(container, actual)

	switch event.Kind {
	case EventTCPListen:
		// A listening socket has no remote peer: the tracepoint's
		// destination half is zero. The bind address lives in the
		// source half of the tuple.
		l.store.ObserveListen(store.ListenEndpoint{
			Container:  container,
			ListenAddr: event.Tuple.Source(),
			Proxy:      "false",
			Value:      1,
		})
	case EventTCPSuccessfulConnect:
		l.store.IncSuccessfulConnect(storeEvent)
		l.store.IncActiveConnection(storeEvent)
	case EventTCPFailedConnect:
		l.store.IncFailedConnect(storeEvent)
	case EventTCPClose:
		l.store.DecActiveConnection(storeEvent)
	case EventTCPRetransmit:
		l.store.IncRetransmit(storeEvent)
	case EventTCPBytesSent:
		l.store.AddBytesSent(storeEvent)
	case EventTCPBytesReceived:
		l.store.AddBytesReceived(storeEvent)
	case EventTCPInboundAccept:
		inbound := event.ToInboundStoreEvent(container)
		l.store.IncInboundAccept(inbound)
		l.store.IncInboundActive(inbound)
	case EventTCPInboundClose:
		l.store.DecInboundActive(event.ToInboundStoreEvent(container))
	case EventTCPInboundBytesSent:
		l.store.AddInboundBytesSent(event.ToInboundStoreEvent(container))
	case EventTCPInboundBytesRecv:
		l.store.AddInboundBytesReceived(event.ToInboundStoreEvent(container))
	default:
		l.logger.Debug("unhandled tcp event kind", "kind", uint8(event.Kind))
	}
}

func (l *Loader) dispatchNAT(event NATEvent) {
	if l.dropIPv6 && (event.Orig.IsIPv6() || event.Reply.IsIPv6()) {
		return
	}
	// The "reply" tuple's source is what packets actually come back from,
	// which is the post-DNAT remote endpoint.
	original := event.Orig.Destination()
	actual := event.Reply.Source()
	if original == "" || actual == "" || original == actual {
		return
	}
	l.nat.put(original, actual)
}

func (l *Loader) dispatchL7(event L7Event) {
	if l.dropIPv6 && event.Tuple.IsIPv6() {
		return
	}
	container := l.resolveContainer(event.CgroupID, event.PID)
	if container.ContainerID == "" {
		return
	}
	dst := event.Tuple.Destination()
	actual := l.actualDestination(dst)

	proto, _ := l.classifier.ProtocolForPort(event.Tuple.DestinationPort)
	if proto == "" {
		proto, _ = l.classifier.ProtocolForPort(event.Tuple.SourcePort)
	}
	// When no registered port matches, fall back to content-based
	// autodiscovery. The verdict is cached per flow so multiplexed
	// protocols (HTTP/2) attribute later, non-self-identifying packets on
	// the same connection.
	if proto == "" {
		if cached, ok := l.flows.getRefresh(event.Tuple); ok {
			proto = cached
		} else if sniffed, ok := sniffProtocol(event.Direction, event.Payload); ok {
			proto = sniffed
			l.flows.put(event.Tuple, sniffed)
		}
	}
	if proto == "" {
		return
	}

	switch event.Direction {
	case DirRequest:
		l.handleProtocolRequest(proto, event, container, dst, actual)
	case DirResponse:
		l.handleProtocolResponse(proto, event, container, dst, actual)
	}
}

// sniffProtocol inspects an L7 payload to classify a flow whose ports are not
// registered with the classifier. It currently detects cleartext HTTP/1.x and
// HTTP/2 (h2c): a request is HTTP if it carries a request line or the HTTP/2
// connection preface; a response is HTTP if it carries a status line or a
// decodable HTTP/2 ":status". TLS-wrapped traffic is encrypted and never
// matches.
func sniffProtocol(dir Direction, payload []byte) (store.Protocol, bool) {
	switch dir {
	case DirRequest:
		if _, ok := protocol.ParseHTTPRequest(payload); ok {
			return store.ProtocolHTTP, true
		}
		if protocol.IsHTTP2Preface(payload) {
			return store.ProtocolHTTP, true
		}
	case DirResponse:
		if _, ok := protocol.ParseHTTPStatus(payload); ok {
			return store.ProtocolHTTP, true
		}
		if _, ok := protocol.ParseHTTP2Status(payload); ok {
			return store.ProtocolHTTP, true
		}
	}
	return "", false
}

func (l *Loader) handleProtocolRequest(proto store.Protocol, event L7Event, container store.ContainerLabels, dst, actual string) {
	correlation := protocolCorrelation(proto, DirRequest, event.Payload)
	if correlation == "" {
		correlation = dst
	}
	key := protocol.RequestKey{
		ContainerID:       container.ContainerID,
		Destination:       dst,
		ActualDestination: actual,
		CorrelationID:     correlation,
		Protocol:          proto,
	}
	l.tracker.Start(key, time.Now())

	if proto == store.ProtocolHTTP {
		if request, ok := protocol.ParseHTTPRequest(event.Payload); ok && request.URL != "" {
			l.urls.put(urlFlowKey{
				containerID:       container.ContainerID,
				destination:       dst,
				actualDestination: actual,
			}, request.URL)
		}
	}
}

func (l *Loader) handleProtocolResponse(proto store.Protocol, event L7Event, container store.ContainerLabels, dst, actual string) {
	correlation := protocolCorrelation(proto, DirResponse, event.Payload)
	if correlation == "" {
		correlation = dst
	}
	key := protocol.RequestKey{
		ContainerID:       container.ContainerID,
		Destination:       dst,
		ActualDestination: actual,
		CorrelationID:     correlation,
		Protocol:          proto,
	}
	duration, ok := l.tracker.Finish(key, time.Now())
	if !ok {
		duration = event.Elapsed
	}

	url := ""
	if proto == store.ProtocolHTTP {
		url, _ = l.urls.take(urlFlowKey{
			containerID:       container.ContainerID,
			destination:       dst,
			actualDestination: actual,
		})
	}

	status := protocolStatus(proto, event.Payload)
	l.store.ObserveProtocol(store.ProtocolEvent{
		Protocol:  proto,
		Container: container,
		Endpoint:  store.Endpoint{Destination: dst, ActualDestination: actual},
		Status:    protocol.NormalizeStatus(proto, status),
		URL:       url,
		Duration:  duration,
	})
}

func (l *Loader) dispatchDNS(event DNSWireEvent) {
	l.dnsStats.recordsReceived.Add(1)

	// NOTE: we deliberately do NOT drop on event.Tuple.IsIPv6() here. The
	// DNS tuple family reflects the resolver *socket* family (skc_family),
	// which is commonly AF_INET6 even for A-record lookups on dual-stack
	// hosts. Filtering on it would discard all IPv4 DNS data. IPv6 DNS
	// metrics are instead filtered per-question (AAAA) and per-answer
	// (IPv6 address) below.
	if event.Direction != DirResponse {
		l.dnsStats.nonResponse.Add(1)
		l.logger.Debug("dns: skipped non-response event",
			"direction", uint8(event.Direction),
			"cgroup_id", event.CgroupID,
			"pid", event.PID,
			"payload_len", event.PayloadLen)
		return
	}

	container := l.resolveContainer(event.CgroupID, event.PID)
	if container.ContainerID == "" {
		l.dnsStats.containerMissing.Add(1)
		l.logger.Debug("dns: dropped, container not resolved",
			"cgroup_id", event.CgroupID,
			"pid", event.PID,
			"src", event.Tuple.Source(),
			"dst", event.Tuple.Destination(),
			"payload_len", event.PayloadLen)
		return
	}

	parsed, ok := protocol.ParseDNSResponse(event.Payload)
	if !ok {
		l.dnsStats.parseFailed.Add(1)
		l.logger.Debug("dns: response parse failed",
			"container_id", container.ContainerID,
			"payload_len", len(event.Payload))
		return
	}

	if len(parsed.Questions) == 0 {
		l.dnsStats.noQuestions.Add(1)
		l.logger.Debug("dns: parsed response had no questions",
			"container_id", container.ContainerID,
			"answers", len(parsed.Answers),
			"status", parsed.Status)
	}

	for _, q := range parsed.Questions {
		if l.dropIPv6 && q.Type == "AAAA" {
			continue
		}
		l.store.ObserveDNS(store.DNSEvent{
			Container:   container,
			Domain:      q.Name,
			RequestType: q.Type,
			Status:      parsed.Status,
			Duration:    0,
		})
		l.dnsStats.requestsObserved.Add(1)
		l.logger.Debug("dns: observed request",
			"container_id", container.ContainerID,
			"domain", q.Name,
			"type", q.Type,
			"status", parsed.Status)
	}
	for _, ans := range parsed.Answers {
		if l.dropIPv6 {
			if addr, err := netip.ParseAddr(ans.IP); err == nil && !addr.Is4() {
				continue
			}
		}
		l.store.SetIPFQDN(store.IPFQDNMapping{
			Container: container,
			IP:        ans.IP,
			FQDN:      ans.Name,
			Value:     1,
		})
		l.dnsStats.mappingsObserved.Add(1)
	}
}

// logDNSStats periodically flushes accumulated DNS pipeline counters at
// info level and warns when two consecutive intervals see zero ringbuf
// records (a strong signal that dns.bpf.o failed to load or the kprobes
// never attached).
func (l *Loader) logDNSStats(ctx context.Context) {
	if dnsStatsInterval <= 0 {
		return
	}
	ticker := time.NewTicker(dnsStatsInterval)
	defer ticker.Stop()

	var emptyTicks int
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			received := l.dnsStats.recordsReceived.Swap(0)
			nonResp := l.dnsStats.nonResponse.Swap(0)
			missing := l.dnsStats.containerMissing.Swap(0)
			parseFail := l.dnsStats.parseFailed.Swap(0)
			noQ := l.dnsStats.noQuestions.Swap(0)
			reqObs := l.dnsStats.requestsObserved.Swap(0)
			mapObs := l.dnsStats.mappingsObserved.Swap(0)

			l.logger.Info("dns pipeline stats",
				"interval", dnsStatsInterval.String(),
				"records_received", received,
				"non_response_skipped", nonResp,
				"container_missing", missing,
				"parse_failed", parseFail,
				"no_questions", noQ,
				"requests_observed", reqObs,
				"ip_fqdn_observed", mapObs)

			if received == 0 {
				emptyTicks++
				if emptyTicks >= 2 {
					l.logger.Warn("dns: no DNS ringbuf events observed for two consecutive intervals; confirm dns.bpf.o loaded and udp_sendmsg/udp_recvmsg kprobes attached",
						"interval", dnsStatsInterval.String())
				}
			} else {
				emptyTicks = 0
			}
		}
	}
}

func (l *Loader) dispatchOOM(event OOMEvent) {
	container := l.resolveContainer(event.CgroupID, event.PID)
	l.store.ObserveOOMKill(store.OOMEvent{
		Container: container,
		VictimPID: event.VictimPID,
	})
}

// resolveContainer maps a BPF event back to a container by cgroup id (the
// strongest signal) or by PID as a fallback. When neither lookup hits the
// returned labels are empty so the metric is still emitted.
func (l *Loader) resolveContainer(cgroupID uint64, pid uint32) store.ContainerLabels {
	if cgroupID != 0 {
		if container, ok := l.identity.ByCgroupID(cgroupID); ok {
			return toLabels(container)
		}
	}
	if pid != 0 {
		if container, ok := l.identity.ByPID(int(pid)); ok {
			return toLabels(container)
		}
	}
	return store.ContainerLabels{}
}

func toLabels(c identity.Container) store.ContainerLabels {
	return store.ContainerLabels{
		ContainerID:   c.ID,
		ContainerName: c.Name,
		PodID:         c.PodID,
	}
}

func splitTracepoint(tp string) (group, name string, ok bool) {
	for i := 0; i < len(tp); i++ {
		if tp[i] == '/' {
			return tp[:i], tp[i+1:], i > 0 && i < len(tp)-1
		}
	}
	return "", "", false
}
