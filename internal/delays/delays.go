// Package delays exposes per-task delay accounting counters via
// /proc/<pid>/schedstat as a portable fallback when taskstats over
// generic netlink is unavailable. /proc/<pid>/schedstat is
// available on every Linux kernel with CONFIG_SCHEDSTATS and requires
// no privileged netlink call.
//
// The Reader aggregates per-process counters into per-container
// totals and writes them into the metric store. Counters are
// monotonic; the store treats them as Prometheus counters.
package delays

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"time"

	"pnet-exporter/internal/identity"
	"pnet-exporter/internal/store"
)

const nanosPerSec = 1_000_000_000.0

// Reader periodically polls /proc/<pid>/schedstat for every live
// container and writes a per-container delay sample into the store.
type Reader struct {
	procRoot string
	identity *identity.Cache
	store    *store.Store
	logger   *slog.Logger
	interval time.Duration
}

// NewReader wires up a Reader. interval governs how often the loop
// fires; 15s is a good default.
func NewReader(procRoot string, ident *identity.Cache, metricStore *store.Store, interval time.Duration, logger *slog.Logger) *Reader {
	if procRoot == "" {
		procRoot = "/proc"
	}
	if interval <= 0 {
		interval = 15 * time.Second
	}
	return &Reader{
		procRoot: procRoot,
		identity: ident,
		store:    metricStore,
		logger:   logger,
		interval: interval,
	}
}

// Run blocks until ctx is cancelled, polling on each tick.
func (r *Reader) Run(ctx context.Context) {
	ticker := time.NewTicker(r.interval)
	defer ticker.Stop()
	r.poll()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			r.poll()
		}
	}
}

func (r *Reader) poll() {
	containers := r.identity.Snapshot()
	for _, container := range containers {
		if container.PID == 0 {
			continue
		}
		sample, err := r.sample(container)
		if err != nil {
			r.logger.Debug("read schedstat", "container", container.ID, "error", err)
			continue
		}
		r.store.RecordResourceDelay(sample)
	}
}

func (r *Reader) sample(container identity.Container) (store.ResourceDelaySample, error) {
	pids, err := r.cgroupPIDs(container)
	if err != nil {
		return store.ResourceDelaySample{}, err
	}
	if len(pids) == 0 {
		// Fall back to the entry PID so we record something even on
		// hosts where cgroup procs files are not readable.
		pids = []int{container.PID}
	}

	var totalRunWaitNS uint64
	var totalIOWaitNS uint64
	for _, pid := range pids {
		runWait, ioWait, err := readSchedStat(r.procRoot, pid)
		if err != nil {
			continue
		}
		totalRunWaitNS += runWait
		totalIOWaitNS += ioWait
	}
	return store.ResourceDelaySample{
		Container: store.ContainerLabels{
			ContainerID:   container.ID,
			ContainerName: container.Name,
			PodID:         container.PodID,
		},
		CPUDelaySeconds: float64(totalRunWaitNS) / nanosPerSec,
		IODelaySeconds:  float64(totalIOWaitNS) / nanosPerSec,
	}, nil
}

// cgroupPIDs returns the PIDs that belong to the container's cgroup.
// On cgroup-v2 hosts the procs file is `/sys/fs/cgroup/<path>/cgroup.procs`.
// When the path is unknown we fall back to the entry PID alone.
func (r *Reader) cgroupPIDs(container identity.Container) ([]int, error) {
	if container.CgroupPath == "" {
		return nil, nil
	}
	path := "/sys/fs/cgroup" + container.CgroupPath + "/cgroup.procs"
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read cgroup.procs %s: %w", path, err)
	}
	var out []int
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		pid, err := strconv.Atoi(line)
		if err != nil {
			continue
		}
		out = append(out, pid)
	}
	return out, nil
}

// readSchedStat parses /proc/<pid>/schedstat. The fields are:
//
//	field 1: cumulative time on CPU in nanoseconds
//	field 2: cumulative time spent waiting on a runqueue (ns) — the cpu_delay metric
//	field 3: number of timeslices on this CPU
//
// /proc/<pid>/schedstat does not expose an I/O delay counter; we
// approximate that with /proc/<pid>/status `delayacct_blkio_ticks`.
func readSchedStat(procRoot string, pid int) (runWaitNS, ioWaitNS uint64, err error) {
	statPath := fmt.Sprintf("%s/%d/schedstat", procRoot, pid)
	data, err := os.ReadFile(statPath)
	if err != nil {
		return 0, 0, fmt.Errorf("read schedstat for pid %d: %w", pid, err)
	}
	fields := strings.Fields(string(data))
	if len(fields) < 2 {
		return 0, 0, fmt.Errorf("malformed schedstat for pid %d", pid)
	}
	runWaitNS, err = strconv.ParseUint(fields[1], 10, 64)
	if err != nil {
		return 0, 0, fmt.Errorf("parse schedstat run_wait for pid %d: %w", pid, err)
	}

	// blkio ticks (clock ticks) come from /proc/<pid>/stat field 42.
	statBytes, err := os.ReadFile(fmt.Sprintf("%s/%d/stat", procRoot, pid))
	if err != nil {
		return runWaitNS, 0, nil
	}
	rest := string(statBytes)
	// Skip past the comm field (parenthesised) which may contain
	// spaces.
	if idx := strings.LastIndexByte(rest, ')'); idx >= 0 {
		rest = rest[idx+1:]
	}
	stats := strings.Fields(rest)
	// After dropping pid + comm, field "delayacct_blkio_ticks" is at
	// index 39 (the 42nd field overall, minus 3 for the dropped
	// fields). Defensive bounds-check to avoid panicking on older
	// kernels.
	if len(stats) > 39 {
		if ticks, err := strconv.ParseUint(stats[39], 10, 64); err == nil {
			ioWaitNS = ticks * 10_000_000 // 100Hz tick -> 10ms -> 1e7 ns
		}
	}
	return runWaitNS, ioWaitNS, nil
}
