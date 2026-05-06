//go:build linux

package ebpf

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

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
			return fmt.Errorf("new collection %s: %w", descriptor.Object, err)
		}

		prog, ok := collection.Programs[descriptor.Program]
		if !ok {
			collection.Close()
			return fmt.Errorf("program %s not found in %s", descriptor.Program, descriptor.Object)
		}

		group, name, ok := splitTracepoint(descriptor.TracepointTP)
		if !ok {
			collection.Close()
			return fmt.Errorf("invalid tracepoint %q", descriptor.TracepointTP)
		}

		tp, err := link.Tracepoint(group, name, prog, nil)
		if err != nil {
			collection.Close()
			return fmt.Errorf("attach tracepoint %s: %w", descriptor.TracepointTP, err)
		}

		l.state.collections = append(l.state.collections, collection)
		l.state.links = append(l.state.links, tp)

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

	l.logger.Info("eBPF loader started",
		"programs", len(l.state.collections),
		"links", len(l.state.links))
	return nil
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

		event, err := DecodeTCPEvent(record.RawSample)
		if err != nil {
			l.logger.Debug("decode tcp event", "error", err, "size", len(record.RawSample))
			continue
		}

		l.dispatch(event)
	}
}
