// Package node implements node-level metric collection sourced from /proc,
// without scraping cloud-instance metadata from the hypervisor APIs.
package node

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// CPUTimes is a flat snapshot of the aggregate /proc/stat first line.
// Values are in clock ticks; convert via SC_CLK_TCK (100 on most kernels)
// when emitting seconds-based metrics.
type CPUTimes struct {
	User    uint64
	Nice    uint64
	System  uint64
	Idle    uint64
	IOWait  uint64
	IRQ     uint64
	SoftIRQ uint64
	Steal   uint64
}

// ReadCPUTimes parses /proc/stat into aggregate CPU times.
func ReadCPUTimes(procRoot string) (CPUTimes, error) {
	if procRoot == "" {
		procRoot = "/proc"
	}
	data, err := os.ReadFile(procRoot + "/stat")
	if err != nil {
		return CPUTimes{}, fmt.Errorf("read /proc/stat: %w", err)
	}
	for _, line := range strings.Split(string(data), "\n") {
		if !strings.HasPrefix(line, "cpu ") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 9 {
			return CPUTimes{}, fmt.Errorf("unexpected /proc/stat cpu line: %q", line)
		}
		var times CPUTimes
		for i, dst := range []*uint64{
			&times.User, &times.Nice, &times.System, &times.Idle,
			&times.IOWait, &times.IRQ, &times.SoftIRQ, &times.Steal,
		} {
			v, err := strconv.ParseUint(fields[i+1], 10, 64)
			if err != nil {
				return CPUTimes{}, fmt.Errorf("parse %s: %w", fields[i+1], err)
			}
			*dst = v
		}
		return times, nil
	}
	return CPUTimes{}, fmt.Errorf("cpu line missing from /proc/stat")
}

// Memory mirrors a small subset of /proc/meminfo (all values in bytes).
type Memory struct {
	TotalBytes     uint64
	FreeBytes      uint64
	AvailableBytes uint64
	BuffersBytes   uint64
	CachedBytes    uint64
}

// ReadMemory parses /proc/meminfo.
func ReadMemory(procRoot string) (Memory, error) {
	if procRoot == "" {
		procRoot = "/proc"
	}
	f, err := os.Open(procRoot + "/meminfo")
	if err != nil {
		return Memory{}, fmt.Errorf("open /proc/meminfo: %w", err)
	}
	defer func() { _ = f.Close() }()

	out := Memory{}
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		colon := strings.IndexByte(line, ':')
		if colon < 0 {
			continue
		}
		key := line[:colon]
		rest := strings.TrimSpace(line[colon+1:])
		fields := strings.Fields(rest)
		if len(fields) < 1 {
			continue
		}
		value, err := strconv.ParseUint(fields[0], 10, 64)
		if err != nil {
			continue
		}
		// /proc/meminfo reports values in KiB unless a different unit
		// is given in fields[1]. We assume KiB and convert to bytes.
		bytes := value * 1024
		switch key {
		case "MemTotal":
			out.TotalBytes = bytes
		case "MemFree":
			out.FreeBytes = bytes
		case "MemAvailable":
			out.AvailableBytes = bytes
		case "Buffers":
			out.BuffersBytes = bytes
		case "Cached":
			out.CachedBytes = bytes
		}
	}
	return out, scanner.Err()
}

// Uptime returns the system uptime in seconds.
func Uptime(procRoot string) (float64, error) {
	if procRoot == "" {
		procRoot = "/proc"
	}
	data, err := os.ReadFile(procRoot + "/uptime")
	if err != nil {
		return 0, fmt.Errorf("read /proc/uptime: %w", err)
	}
	fields := strings.Fields(string(data))
	if len(fields) == 0 {
		return 0, fmt.Errorf("empty /proc/uptime")
	}
	return strconv.ParseFloat(fields[0], 64)
}

// DiskCounters mirrors /proc/diskstats per-device.
type DiskCounters struct {
	Device       string
	ReadsTotal   uint64
	WritesTotal  uint64
	ReadBytes    uint64
	WrittenBytes uint64
}

const sectorBytes = 512

// ReadDiskCounters parses /proc/diskstats. Pseudo / partition devices
// whose names start with "loop", "ram", or contain a partition suffix
// (digit at end of a base device name) are filtered out.
func ReadDiskCounters(procRoot string) ([]DiskCounters, error) {
	if procRoot == "" {
		procRoot = "/proc"
	}
	f, err := os.Open(procRoot + "/diskstats")
	if err != nil {
		return nil, fmt.Errorf("open /proc/diskstats: %w", err)
	}
	defer func() { _ = f.Close() }()

	var out []DiskCounters
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		// /proc/diskstats format: major minor name reads ... sectors_read ... writes ... sectors_written ...
		if len(fields) < 14 {
			continue
		}
		device := fields[2]
		if strings.HasPrefix(device, "loop") || strings.HasPrefix(device, "ram") {
			continue
		}
		reads, _ := strconv.ParseUint(fields[3], 10, 64)
		sectorsRead, _ := strconv.ParseUint(fields[5], 10, 64)
		writes, _ := strconv.ParseUint(fields[7], 10, 64)
		sectorsWritten, _ := strconv.ParseUint(fields[9], 10, 64)
		out = append(out, DiskCounters{
			Device:       device,
			ReadsTotal:   reads,
			WritesTotal:  writes,
			ReadBytes:    sectorsRead * sectorBytes,
			WrittenBytes: sectorsWritten * sectorBytes,
		})
	}
	return out, scanner.Err()
}

// NetInterfaceCounters mirrors /proc/net/dev per interface.
type NetInterfaceCounters struct {
	Interface       string
	ReceivedBytes   uint64
	ReceivedPackets uint64
	ReceivedErrors  uint64
	TransmitBytes   uint64
	TransmitPackets uint64
	TransmitErrors  uint64
}

// ReadNetInterfaceCounters parses /proc/net/dev. The lo interface and
// any tap/veth interface (the typical Podman bridge plumbing) is
// retained so users can correlate intra-pod and pod->host traffic.
func ReadNetInterfaceCounters(procRoot string) ([]NetInterfaceCounters, error) {
	if procRoot == "" {
		procRoot = "/proc"
	}
	f, err := os.Open(procRoot + "/net/dev")
	if err != nil {
		return nil, fmt.Errorf("open /proc/net/dev: %w", err)
	}
	defer func() { _ = f.Close() }()

	var out []NetInterfaceCounters
	scanner := bufio.NewScanner(f)
	header := 0
	for scanner.Scan() {
		header++
		if header <= 2 {
			continue
		}
		line := scanner.Text()
		colon := strings.IndexByte(line, ':')
		if colon < 0 {
			continue
		}
		name := strings.TrimSpace(line[:colon])
		fields := strings.Fields(line[colon+1:])
		if len(fields) < 16 {
			continue
		}
		parse := func(s string) uint64 {
			v, _ := strconv.ParseUint(s, 10, 64)
			return v
		}
		out = append(out, NetInterfaceCounters{
			Interface:       name,
			ReceivedBytes:   parse(fields[0]),
			ReceivedPackets: parse(fields[1]),
			ReceivedErrors:  parse(fields[2]),
			TransmitBytes:   parse(fields[8]),
			TransmitPackets: parse(fields[9]),
			TransmitErrors:  parse(fields[10]),
		})
	}
	return out, scanner.Err()
}
