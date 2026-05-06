//go:build !linux

package ebpf

import "context"

// loaderState carries platform-specific state for the Loader. On non-Linux
// platforms there is nothing to track, so the struct is intentionally
// empty: the Loader is a no-op and the rest of the project can still be
// built and unit-tested.
type loaderState struct{}

// Start logs a warning and returns nil. eBPF observability requires a
// recent Linux kernel; running the exporter on any other platform is
// supported only for development of the surrounding code.
func (l *Loader) Start(_ context.Context) error {
	l.logger.Warn("eBPF is only supported on Linux; collector will stay idle",
		"bpf_dir", l.cfg.BPFDir)
	return nil
}

// Close is a no-op on non-Linux platforms.
func (l *Loader) Close() {}
