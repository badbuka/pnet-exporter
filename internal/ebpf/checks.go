package ebpf

import (
	"fmt"
	"os"
	"path/filepath"
)

type StartupCheck struct {
	Name     string
	Required bool
	Err      error
}

// CheckKernelSupport returns a list of kernel-feature probes the
// exporter wants. Required failures abort startup; optional ones are
// logged and the corresponding BPF objects will simply fail to attach,
// which the loader handles gracefully.
func CheckKernelSupport(sysfs string) []StartupCheck {
	tracingRoot := filepath.Join(sysfs, "kernel", "tracing")
	debugfsRoot := filepath.Join(sysfs, "kernel", "debug", "tracing")
	// Some distros only mount debugfs; tolerate either layout when
	// checking for tracepoint availability.
	probeTracepoint := func(name, path string, required bool) StartupCheck {
		if _, err := os.Stat(path); err == nil {
			return StartupCheck{Name: name}
		}
		alt := filepath.Join(debugfsRoot, path[len(tracingRoot):])
		if _, err := os.Stat(alt); err == nil {
			return StartupCheck{Name: name}
		}
		return StartupCheck{Name: name, Required: required, Err: fmt.Errorf("%s missing at %s and %s", name, path, alt)}
	}
	return []StartupCheck{
		checkPath("btf-vmlinux", filepath.Join(sysfs, "kernel", "btf", "vmlinux"), true),
		probeTracepoint("tracepoint-inet-sock-set-state",
			filepath.Join(tracingRoot, "events", "sock", "inet_sock_set_state"), true),
		probeTracepoint("tracepoint-tcp-retransmit-skb",
			filepath.Join(tracingRoot, "events", "tcp", "tcp_retransmit_skb"), false),
		checkPath("kallsyms", "/proc/kallsyms", false),
	}
}

func checkPath(name, path string, required bool) StartupCheck {
	_, err := os.Stat(path)
	if err != nil {
		err = fmt.Errorf("%s is unavailable at %s: %w", name, path, err)
	}
	return StartupCheck{Name: name, Required: required, Err: err}
}
