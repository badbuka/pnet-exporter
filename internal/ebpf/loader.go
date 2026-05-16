package ebpf

import (
	"log/slog"
	"time"

	"pnet-exporter/internal/config"
	"pnet-exporter/internal/identity"
	"pnet-exporter/internal/protocol"
	"pnet-exporter/internal/store"
)

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
		Object: "tcp_conntrack.bpf.o",
		Programs: []programAttachment{
			{Program: "handle_conntrack_confirm", Kind: attachKprobe, Target: "__nf_conntrack_confirm"},
		},
	},
	{
		Object: "l7.bpf.o",
		Programs: []programAttachment{
			{Program: "l7_tcp_sendmsg", Kind: attachKprobe, Target: "tcp_sendmsg"},
			{Program: "l7_tcp_recvmsg", Kind: attachKprobe, Target: "tcp_recvmsg"},
		},
	},
	{
		Object: "dns.bpf.o",
		Programs: []programAttachment{
			{Program: "dns_udp_sendmsg", Kind: attachKprobe, Target: "udp_sendmsg"},
			{Program: "dns_udp_recvmsg", Kind: attachKprobe, Target: "udp_recvmsg"},
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
	nat      *NATCache

	classifier protocol.Classifier
	tracker    *protocol.RequestTracker

	state loaderState
}

func NewLoader(cfg config.EBPFConfig, classifier protocol.Classifier, identity *identity.Cache, metricStore *store.Store, logger *slog.Logger) *Loader {
	return &Loader{
		cfg:        cfg,
		identity:   identity,
		store:      metricStore,
		logger:     logger,
		nat:        NewNATCache(5 * time.Minute),
		classifier: classifier,
		tracker:    protocol.NewRequestTracker(30 * time.Second),
	}
}

// NATCache exposes the loader's NAT cache so other components (latency
// prober, integration tests) can consult or seed it.
func (l *Loader) NATCache() *NATCache { return l.nat }

func (l *Loader) dispatchTCP(event TCPEvent) {
	container := l.resolveContainer(event.CgroupID, event.PID)
	dst := event.Tuple.Destination()
	actual := l.nat.Lookup(dst)
	storeEvent := event.ToStoreEvent(container, actual)

	switch event.Kind {
	case EventTCPListen:
		l.store.ObserveListen(store.ListenEndpoint{
			Container:  container,
			ListenAddr: event.Tuple.Destination(),
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
	default:
		l.logger.Debug("unhandled tcp event kind", "kind", uint8(event.Kind))
	}
}

func (l *Loader) dispatchNAT(event NATEvent) {
	// The "reply" tuple's source is what packets actually come back from,
	// which is the post-DNAT remote endpoint.
	original := event.Orig.Destination()
	actual := event.Reply.Source()
	if original == "" || actual == "" || original == actual {
		return
	}
	l.nat.Put(original, actual)
}

func (l *Loader) dispatchL7(event L7Event) {
	container := l.resolveContainer(event.CgroupID, event.PID)
	if container.ContainerID == "" {
		return
	}
	dst := event.Tuple.Destination()
	actual := l.nat.Lookup(dst)

	proto, _ := l.classifier.ProtocolForPort(event.Tuple.DestinationPort)
	if proto == "" {
		proto, _ = l.classifier.ProtocolForPort(event.Tuple.SourcePort)
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

func (l *Loader) handleProtocolRequest(proto store.Protocol, event L7Event, container store.ContainerLabels, dst, actual string) {
	correlation := protocolCorrelation(proto, event.Payload)
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
}

func (l *Loader) handleProtocolResponse(proto store.Protocol, event L7Event, container store.ContainerLabels, dst, actual string) {
	correlation := protocolCorrelation(proto, event.Payload)
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

	status := protocolStatus(proto, event.Payload)
	l.store.ObserveProtocol(store.ProtocolEvent{
		Protocol:  proto,
		Container: container,
		Endpoint:  store.Endpoint{Destination: dst, ActualDestination: actual},
		Status:    protocol.NormalizeStatus(proto, status),
		Duration:  duration,
	})
}

func (l *Loader) dispatchDNS(event DNSWireEvent) {
	container := l.resolveContainer(event.CgroupID, event.PID)
	if container.ContainerID == "" {
		return
	}
	if event.Direction != DirResponse {
		return
	}
	parsed, ok := protocol.ParseDNSResponse(event.Payload)
	if !ok {
		return
	}
	for _, q := range parsed.Questions {
		l.store.ObserveDNS(store.DNSEvent{
			Container:   container,
			Domain:      q.Name,
			RequestType: q.Type,
			Status:      parsed.Status,
			Duration:    0,
		})
	}
	for _, ans := range parsed.Answers {
		l.store.SetIPFQDN(store.IPFQDNMapping{
			Container: container,
			IP:        ans.IP,
			FQDN:      ans.Name,
			Value:     1,
		})
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
