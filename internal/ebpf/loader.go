package ebpf

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"path/filepath"

	"pnet-exporter/internal/config"
	"pnet-exporter/internal/identity"
	"pnet-exporter/internal/store"

	ciliumebpf "github.com/cilium/ebpf"
)

type Loader struct {
	cfg      config.EBPFConfig
	identity *identity.Cache
	store    *store.Store
	logger   *slog.Logger
	objects  []*ciliumebpf.Collection
}

func NewLoader(cfg config.EBPFConfig, identity *identity.Cache, store *store.Store, logger *slog.Logger) *Loader {
	return &Loader{cfg: cfg, identity: identity, store: store, logger: logger}
}

func (l *Loader) Start(_ context.Context) error {
	objects := []string{
		"tcp_state.bpf.o",
		"tcp_retransmit.bpf.o",
		"tcp_bytes.bpf.o",
		"sys_connect.bpf.o",
		"protocols.bpf.o",
	}

	for _, name := range objects {
		path := filepath.Join(l.cfg.BPFDir, name)
		if _, err := os.Stat(path); err != nil {
			if errors.Is(err, os.ErrNotExist) {
				l.logger.Warn("compiled eBPF object is missing; collector will stay idle", "path", path)
				continue
			}
			return err
		}
		spec, err := ciliumebpf.LoadCollectionSpec(path)
		if err != nil {
			return err
		}
		collection, err := ciliumebpf.NewCollection(spec)
		if err != nil {
			return err
		}
		l.objects = append(l.objects, collection)
	}

	l.logger.Info("eBPF loader started", "objects", len(l.objects))
	return nil
}

func (l *Loader) Close() {
	for _, object := range l.objects {
		object.Close()
	}
}

func (l *Loader) IngestTCPEvent(event TCPEvent) {
	tcpEvent := store.TCPEvent{
		Container: event.Container,
		Endpoint: store.Endpoint{
			Destination:       event.Tuple.Destination(),
			ActualDestination: event.ActualDestination,
		},
		Bytes: event.Value,
		Value: float64(event.Value),
	}

	switch event.Kind {
	case EventTCPListen:
		l.store.ObserveListen(store.ListenEndpoint{
			Container:  event.Container,
			ListenAddr: event.Tuple.Destination(),
			Proxy:      "false",
			Value:      1,
		})
	case EventTCPSuccessfulConnect:
		l.store.IncSuccessfulConnect(tcpEvent)
	case EventTCPFailedConnect:
		l.store.IncFailedConnect(tcpEvent)
	case EventTCPActiveConnections:
		l.store.SetActiveConnections(tcpEvent)
	case EventTCPRetransmit:
		l.store.IncRetransmit(tcpEvent)
	case EventTCPBytesSent:
		l.store.AddBytesSent(tcpEvent)
	case EventTCPBytesReceived:
		l.store.AddBytesReceived(tcpEvent)
	}
}
