package ebpf

import (
	"log/slog"

	"pnet-exporter/internal/config"
	"pnet-exporter/internal/identity"
	"pnet-exporter/internal/store"
)

// programDescriptor describes one compiled BPF object: the file name, the
// program name inside it, and the (group, name) tracepoint it should be
// attached to.
type programDescriptor struct {
	Object       string
	Program      string
	TracepointTP string // "group/name", e.g. "sock/inet_sock_set_state"
}

// programs is the canonical list of BPF programs the loader ships.
//
// New programs added here must:
//  1. live in bpf/<Object>.c, building to <Object>.o,
//  2. expose a function with `SEC("tracepoint/<TracepointTP>")`,
//  3. push events through the shared `events` ring buffer.
var programs = []programDescriptor{
	{
		Object:       "tcp_state.bpf.o",
		Program:      "handle_inet_sock_set_state",
		TracepointTP: "sock/inet_sock_set_state",
	},
	{
		Object:       "tcp_retransmit.bpf.o",
		Program:      "handle_tcp_retransmit_skb",
		TracepointTP: "tcp/tcp_retransmit_skb",
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

	state loaderState
}

func NewLoader(cfg config.EBPFConfig, identity *identity.Cache, store *store.Store, logger *slog.Logger) *Loader {
	return &Loader{cfg: cfg, identity: identity, store: store, logger: logger}
}

func (l *Loader) dispatch(event TCPEvent) {
	container := l.resolveContainer(event)
	storeEvent := event.ToStoreEvent(container)

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
	case EventTCPFailedConnect:
		l.store.IncFailedConnect(storeEvent)
	case EventTCPActiveConnections:
		l.store.SetActiveConnections(storeEvent)
	case EventTCPRetransmit:
		l.store.IncRetransmit(storeEvent)
	case EventTCPBytesSent:
		l.store.AddBytesSent(storeEvent)
	case EventTCPBytesReceived:
		l.store.AddBytesReceived(storeEvent)
	default:
		l.logger.Debug("unhandled BPF event kind", "kind", uint8(event.Kind))
	}
}

// resolveContainer maps a BPF event back to a container by cgroup id (the
// strongest signal) or by PID as a fallback. When neither lookup hits the
// returned labels are empty so the metric is still emitted.
func (l *Loader) resolveContainer(event TCPEvent) store.ContainerLabels {
	if event.CgroupID != 0 {
		if container, ok := l.identity.ByCgroupID(event.CgroupID); ok {
			return toLabels(container)
		}
	}
	if event.PID != 0 {
		if container, ok := l.identity.ByPID(int(event.PID)); ok {
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
