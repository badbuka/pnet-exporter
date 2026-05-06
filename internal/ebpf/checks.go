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

func CheckKernelSupport(sysfs string) []StartupCheck {
	return []StartupCheck{
		checkPath("btf-vmlinux", filepath.Join(sysfs, "kernel", "btf", "vmlinux"), true),
		checkPath("tracepoint-inet-sock-set-state", filepath.Join(sysfs, "kernel", "tracing", "events", "sock", "inet_sock_set_state"), true),
		checkPath("tracepoint-tcp-retransmit-skb", filepath.Join(sysfs, "kernel", "tracing", "events", "tcp", "tcp_retransmit_skb"), false),
	}
}

func checkPath(name, path string, required bool) StartupCheck {
	_, err := os.Stat(path)
	if err != nil {
		err = fmt.Errorf("%s is unavailable at %s: %w", name, path, err)
	}
	return StartupCheck{Name: name, Required: required, Err: err}
}
