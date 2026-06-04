// Package resources exposes per-container resource-utilization metrics
// (CPU, memory, block I/O and PSI pressure) read from the cgroup v2
// control files of each live container.
//
// The Reader polls on an interval, reading the cgroup directory at
// {SysFS}/fs/cgroup{CgroupPath} for every container reported by the
// identity cache, and writes a per-container sample into the metric
// store. Counter values (cpu.stat, io.stat, *.pressure totals) are the
// kernel's running totals; memory.* values are instantaneous gauges.
package resources

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"pnet-exporter/internal/identity"
	"pnet-exporter/internal/store"
)

const (
	microsPerSec = 1_000_000.0
)

// Reader periodically reads cgroup v2 utilization files for every live
// container and records a sample into the store.
type Reader struct {
	cgroupRoot string
	identity   *identity.Cache
	store      *store.Store
	logger     *slog.Logger
	interval   time.Duration
}

// NewReader wires up a Reader. sysFS is the sysfs root (e.g. /sys); the
// cgroup v2 hierarchy is expected under {sysFS}/fs/cgroup. interval
// governs the poll cadence; 15s is a good default.
func NewReader(sysFS string, ident *identity.Cache, metricStore *store.Store, interval time.Duration, logger *slog.Logger) *Reader {
	if sysFS == "" {
		sysFS = "/sys"
	}
	if interval <= 0 {
		interval = 15 * time.Second
	}
	return &Reader{
		cgroupRoot: filepath.Join(sysFS, "fs", "cgroup"),
		identity:   ident,
		store:      metricStore,
		logger:     logger,
		interval:   interval,
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
		if container.CgroupPath == "" {
			continue
		}
		sample := r.sample(container)
		r.store.RecordResourceUsage(sample)
	}
}

func (r *Reader) sample(container identity.Container) store.ResourceUsageSample {
	base := filepath.Join(r.cgroupRoot, container.CgroupPath)
	sample := store.ResourceUsageSample{
		Container: store.ContainerLabels{
			ContainerID:   container.ID,
			ContainerName: container.Name,
			PodID:         container.PodID,
		},
	}

	if data, err := os.ReadFile(filepath.Join(base, "cpu.stat")); err == nil {
		applyCPUStat(&sample, string(data))
	} else {
		r.logger.Debug("read cpu.stat", "container", container.ID, "error", err)
	}

	if v, ok := readUint(filepath.Join(base, "memory.current")); ok {
		sample.MemoryUsageBytes = float64(v)
	}
	if v, ok := readUint(filepath.Join(base, "memory.peak")); ok {
		sample.MemoryPeakBytes = float64(v)
		sample.HasMemoryPeak = true
	}
	if data, err := os.ReadFile(filepath.Join(base, "memory.max")); err == nil {
		if v, ok := parseMemoryMax(string(data)); ok {
			sample.MemoryLimitBytes = float64(v)
			sample.HasMemoryLimit = true
		}
	}

	if data, err := os.ReadFile(filepath.Join(base, "io.stat")); err == nil {
		applyIOStat(&sample, string(data))
	}

	if data, err := os.ReadFile(filepath.Join(base, "cpu.pressure")); err == nil {
		some, full, ok := parsePressure(string(data))
		if ok {
			sample.CPUPressureSomeSeconds = some
			sample.CPUPressureFullSeconds = full
			sample.HasCPUPressure = true
		}
	}
	if data, err := os.ReadFile(filepath.Join(base, "memory.pressure")); err == nil {
		some, full, ok := parsePressure(string(data))
		if ok {
			sample.MemoryPressureSomeSeconds = some
			sample.MemoryPressureFullSeconds = full
			sample.HasMemoryPressure = true
		}
	}
	if data, err := os.ReadFile(filepath.Join(base, "io.pressure")); err == nil {
		some, full, ok := parsePressure(string(data))
		if ok {
			sample.IOPressureSomeSeconds = some
			sample.IOPressureFullSeconds = full
			sample.HasIOPressure = true
		}
	}

	return sample
}

// applyCPUStat parses cgroup v2 cpu.stat into the sample. Time fields are
// microseconds and converted to seconds; period/throttle counts are
// integers.
//
//	usage_usec 123
//	user_usec 80
//	system_usec 43
//	nr_periods 10
//	nr_throttled 2
//	throttled_usec 500
func applyCPUStat(sample *store.ResourceUsageSample, data string) {
	for _, line := range strings.Split(data, "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 {
			continue
		}
		value, err := strconv.ParseFloat(fields[1], 64)
		if err != nil {
			continue
		}
		switch fields[0] {
		case "usage_usec":
			sample.CPUUsageSeconds = value / microsPerSec
		case "user_usec":
			sample.CPUUserSeconds = value / microsPerSec
		case "system_usec":
			sample.CPUSystemSeconds = value / microsPerSec
		case "nr_periods":
			sample.CPUPeriods = value
		case "nr_throttled":
			sample.CPUThrottledPeriods = value
		case "throttled_usec":
			sample.CPUThrottledSeconds = value / microsPerSec
		}
	}
}

// applyIOStat parses cgroup v2 io.stat, summing per-device byte and op
// counters across all devices.
//
//	8:0 rbytes=1024 wbytes=2048 rios=10 wios=20 dbytes=0 dios=0
func applyIOStat(sample *store.ResourceUsageSample, data string) {
	for _, line := range strings.Split(data, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		for _, field := range fields[1:] {
			key, rawValue, ok := strings.Cut(field, "=")
			if !ok {
				continue
			}
			value, err := strconv.ParseFloat(rawValue, 64)
			if err != nil {
				continue
			}
			switch key {
			case "rbytes":
				sample.IOReadBytes += value
			case "wbytes":
				sample.IOWrittenBytes += value
			case "rios":
				sample.IOReads += value
			case "wios":
				sample.IOWrites += value
			}
		}
	}
}

// parsePressure parses a PSI file (cpu.pressure / memory.pressure /
// io.pressure), returning the cumulative `some` and `full` stall time in
// seconds (the `total=` field is microseconds). cpu.pressure has no
// `full` line, in which case full is 0.
//
//	some avg10=0.00 avg60=0.00 avg300=0.00 total=1234
//	full avg10=0.00 avg60=0.00 avg300=0.00 total=567
func parsePressure(data string) (some, full float64, ok bool) {
	for _, line := range strings.Split(data, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		var total float64
		found := false
		for _, field := range fields[1:] {
			key, rawValue, cut := strings.Cut(field, "=")
			if !cut || key != "total" {
				continue
			}
			value, err := strconv.ParseFloat(rawValue, 64)
			if err != nil {
				continue
			}
			total = value / microsPerSec
			found = true
		}
		if !found {
			continue
		}
		switch fields[0] {
		case "some":
			some = total
			ok = true
		case "full":
			full = total
			ok = true
		}
	}
	return some, full, ok
}

// parseMemoryMax parses memory.max. The literal "max" means no limit is
// set, in which case ok is false.
func parseMemoryMax(data string) (uint64, bool) {
	trimmed := strings.TrimSpace(data)
	if trimmed == "" || trimmed == "max" {
		return 0, false
	}
	value, err := strconv.ParseUint(trimmed, 10, 64)
	if err != nil {
		return 0, false
	}
	return value, true
}

func readUint(path string) (uint64, bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, false
	}
	value, err := strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64)
	if err != nil {
		return 0, false
	}
	return value, true
}
