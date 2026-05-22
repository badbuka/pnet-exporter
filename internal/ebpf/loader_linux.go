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
	collections []*ciliumebpf.Collection
	links       []link.Link
	reader      *ringbuf.Reader
}

// Start loads and attaches every BPF program in `programs`, opens the shared
// ring buffer, and spins up a goroutine that decodes events and dispatches
// them into the store. It returns nil even when individual objects are
// missing, so a partially-built BPF directory does not prevent the rest of
// the exporter from starting.
func (l *Loader) Start(ctx context.Context) error {
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("remove memlock rlimit: %w", err)
	}

	var sharedRingbuf *ciliumebpf.Map

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

		collection, err := ciliumebpf.NewCollection(spec)
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

		if sharedRingbuf == nil {
			if m, ok := collection.Maps["events"]; ok {
				sharedRingbuf = m
			}
		}
	}

	if sharedRingbuf == nil {
		l.logger.Warn("no BPF programs loaded; collector will stay idle")
		return nil
	}

	reader, err := ringbuf.NewReader(sharedRingbuf)
	if err != nil {
		l.Close()
		return fmt.Errorf("open ringbuf reader: %w", err)
	}
	l.state.reader = reader

	go l.consume(ctx)
	go l.runNATJanitor(ctx)
	go l.logDNSStats(ctx)

	l.logger.Info("eBPF loader started",
		"collections", len(l.state.collections),
		"links", len(l.state.links))
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
}

func (l *Loader) consume(ctx context.Context) {
	for {
		record, err := l.state.reader.Read()
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
		EventTCPClose:
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

func (l *Loader) runNATJanitor(ctx context.Context) {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			l.nat.Prune(now)
		}
	}
}
