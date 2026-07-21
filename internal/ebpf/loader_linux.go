//go:build linux

package ebpf

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	ciliumebpf "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

type loaderState struct {
	collections  []*ciliumebpf.Collection
	links        []link.Link
	reader       *ringbuf.Reader
	sharedEvents *ciliumebpf.Map
}

// Start loads and attaches every BPF program in `programs`, opens the shared
// ring buffer, and spins up a goroutine that decodes events and dispatches
// them into the store. It returns nil even when individual objects are
// missing, so a partially-built BPF directory does not prevent the rest of
// the exporter from starting.
//
// Every BPF object declares its own `events SEC(".maps")` ringbuf, but
// userspace can only read from one. We instantiate the ringbuf once from
// the first available spec and inject it into every subsequent collection
// via CollectionOptions.MapReplacements, so all programs publish into the
// single ringbuf the consume goroutine is bound to.
func (l *Loader) Start(ctx context.Context) error {
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("remove memlock rlimit: %w", err)
	}

	for _, descriptor := range programs {
		path := filepath.Join(l.cfg.BPFDir, descriptor.Object)
		if _, err := os.Stat(path); err != nil {
			if errors.Is(err, os.ErrNotExist) {
				l.logger.Warn("compiled eBPF object is missing; skipping",
					"object", descriptor.Object, "path", path)
				continue
			}
			return err
		}

		spec, err := ciliumebpf.LoadCollectionSpec(path)
		if err != nil {
			return fmt.Errorf("load collection spec %s: %w", descriptor.Object, err)
		}

		if l.state.sharedEvents == nil {
			if mapSpec, ok := spec.Maps["events"]; ok {
				m, err := ciliumebpf.NewMap(mapSpec)
				if err != nil {
					return fmt.Errorf("create shared events ringbuf from %s: %w",
						descriptor.Object, err)
				}
				l.state.sharedEvents = m
				l.logger.Debug("created shared events ringbuf",
					"object", descriptor.Object,
					"max_entries", mapSpec.MaxEntries)
			}
		}

		var opts ciliumebpf.CollectionOptions
		if l.state.sharedEvents != nil {
			opts.MapReplacements = map[string]*ciliumebpf.Map{
				"events": l.state.sharedEvents,
			}
		}

		collection, err := ciliumebpf.NewCollectionWithOptions(spec, opts)
		if err != nil {
			l.logger.Warn("load BPF collection failed; skipping",
				"object", descriptor.Object, "error", err)
			continue
		}

		attached := 0
		for _, attachment := range descriptor.Programs {
			prog, ok := collection.Programs[attachment.Program]
			if !ok {
				l.logger.Warn("program not found in collection",
					"object", descriptor.Object, "program", attachment.Program)
				continue
			}
			lk, err := attachProgram(prog, attachment)
			if err != nil {
				l.logger.Warn("attach BPF program failed; skipping",
					"object", descriptor.Object,
					"program", attachment.Program,
					"target", attachment.Target,
					"error", err)
				continue
			}
			l.state.links = append(l.state.links, lk)
			attached++
			l.logger.Debug("attached BPF program",
				"object", descriptor.Object,
				"program", attachment.Program,
				"target", attachment.Target)
		}

		if attached == 0 {
			l.logger.Warn("no programs attached from object; closing collection",
				"object", descriptor.Object)
			collection.Close()
			continue
		}

		l.state.collections = append(l.state.collections, collection)
	}

	if l.state.sharedEvents == nil {
		l.logger.Warn("no BPF programs loaded; collector will stay idle")
		return nil
	}

	reader, err := ringbuf.NewReader(l.state.sharedEvents)
	if err != nil {
		l.Close()
		return fmt.Errorf("open ringbuf reader: %w", err)
	}
	l.state.reader = reader

	go l.consume(ctx)
	go l.runCacheJanitor(ctx)
	go l.logDNSStats(ctx)

	eventsInfo, _ := l.state.sharedEvents.Info()
	l.logger.Info("eBPF loader started",
		"collections", len(l.state.collections),
		"links", len(l.state.links),
		"events_map_id", eventsInfo.ID)
	return nil
}

func attachProgram(prog *ciliumebpf.Program, attachment programAttachment) (link.Link, error) {
	switch attachment.Kind {
	case attachTracepoint:
		group, name, ok := splitTracepoint(attachment.Target)
		if !ok {
			return nil, fmt.Errorf("invalid tracepoint %q", attachment.Target)
		}
		return link.Tracepoint(group, name, prog, nil)
	case attachKprobe:
		return link.Kprobe(attachment.Target, prog, nil)
	case attachKretprobe:
		return link.Kretprobe(attachment.Target, prog, nil)
	default:
		return nil, fmt.Errorf("unknown attach kind %d", attachment.Kind)
	}
}

// Close detaches every program and releases all kernel resources held by
// the loader. Safe to call multiple times.
func (l *Loader) Close() {
	if l.state.reader != nil {
		_ = l.state.reader.Close()
		l.state.reader = nil
	}
	for _, lk := range l.state.links {
		if err := lk.Close(); err != nil {
			l.logger.Warn("close BPF link", "error", err)
		}
	}
	l.state.links = nil
	for _, collection := range l.state.collections {
		collection.Close()
	}
	l.state.collections = nil
	if l.state.sharedEvents != nil {
		_ = l.state.sharedEvents.Close()
		l.state.sharedEvents = nil
	}
}

func (l *Loader) consume(ctx context.Context) {
	// Capture the reader once: Close() nils l.state.reader from another
	// goroutine, and re-reading the field here would race (and panic on
	// a nil *ringbuf.Reader). reader.Read returns ErrClosed once Close
	// closes it, which is this loop's exit signal.
	reader := l.state.reader
	for {
		record, err := reader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) || ctx.Err() != nil {
				return
			}
			l.logger.Warn("ringbuf read", "error", err)
			continue
		}
		l.dispatchRecord(record.RawSample)
	}
}

func (l *Loader) dispatchRecord(raw []byte) {
	kind, ok := PeekKind(raw)
	if !ok {
		return
	}
	switch kind {
	case EventTCPListen, EventTCPSuccessfulConnect, EventTCPFailedConnect,
		EventTCPRetransmit, EventTCPBytesSent, EventTCPBytesReceived,
		EventTCPClose, EventTCPInboundAccept, EventTCPInboundClose,
		EventTCPInboundBytesSent, EventTCPInboundBytesRecv:
		event, err := DecodeTCPEvent(raw)
		if err != nil {
			l.logger.Debug("decode tcp event", "error", err, "size", len(raw))
			return
		}
		l.dispatchTCP(event)
	case EventConntrackNAT:
		event, err := DecodeNATEvent(raw)
		if err != nil {
			l.logger.Debug("decode nat event", "error", err, "size", len(raw))
			return
		}
		l.dispatchNAT(event)
	case EventL7:
		event, err := DecodeL7Event(raw)
		if err != nil {
			l.logger.Debug("decode l7 event", "error", err, "size", len(raw))
			return
		}
		l.dispatchL7(event)
	case EventDNS:
		event, err := DecodeDNSWireEvent(raw)
		if err != nil {
			l.logger.Warn("decode dns event failed",
				"error", err,
				"size", len(raw),
				"expected_min_size", dnsEventWireSize)
			return
		}
		l.dispatchDNS(event)
	case EventOOM:
		event, err := DecodeOOMEvent(raw)
		if err != nil {
			l.logger.Debug("decode oom event", "error", err, "size", len(raw))
			return
		}
		l.dispatchOOM(event)
	default:
		l.logger.Debug("unhandled BPF event kind", "kind", uint8(kind))
	}
}

// runCacheJanitor periodically ages out the loader's bounded caches: the
// conntrack NAT mappings and the per-flow protocol verdicts used by content
// autodiscovery.
func (l *Loader) runCacheJanitor(ctx context.Context) {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			l.nat.prune(now)
			l.flows.prune(now)
			l.urls.prune(now)
			l.tracker.Prune(now)
		}
	}
}
