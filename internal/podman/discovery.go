package podman

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"pnet-exporter/internal/identity"
)

type Discoverer struct {
	socket string
	binary string
	logger *slog.Logger
}

func NewDiscoverer(socket, binary string, logger *slog.Logger) *Discoverer {
	return &Discoverer{socket: socket, binary: binary, logger: logger}
}

func (d *Discoverer) List(ctx context.Context) ([]identity.Container, error) {
	containers, err := d.listViaCLI(ctx)
	if err == nil {
		return containers, nil
	}

	if _, statErr := os.Stat(d.socket); statErr == nil {
		d.logger.Debug("podman socket exists but API client is not wired yet", "socket", d.socket)
	}
	return nil, err
}

func (d *Discoverer) listViaCLI(ctx context.Context) ([]identity.Container, error) {
	cmd := exec.CommandContext(ctx, d.binary, "ps", "--format", "json", "--no-trunc")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("podman ps failed: %w: %s", err, strings.TrimSpace(stderr.String()))
	}

	var rows []psRow
	if err := json.Unmarshal(output, &rows); err != nil {
		return nil, fmt.Errorf("decode podman ps output: %w", err)
	}

	containers := make([]identity.Container, 0, len(rows))
	for _, row := range rows {
		id := row.ID
		if id == "" {
			id = row.UpperID
		}
		if id == "" {
			continue
		}
		container, err := d.inspect(ctx, id)
		if err != nil {
			d.logger.Warn("podman inspect failed", "container_id", row.ID, "error", err)
			continue
		}
		containers = append(containers, container)
	}
	return containers, nil
}

func (d *Discoverer) inspect(ctx context.Context, id string) (identity.Container, error) {
	cmd := exec.CommandContext(ctx, d.binary, "inspect", id, "--format", "json")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	output, err := cmd.Output()
	if err != nil {
		return identity.Container{}, fmt.Errorf("podman inspect failed: %w: %s", err, strings.TrimSpace(stderr.String()))
	}

	var rows []inspectRow
	if err := json.Unmarshal(output, &rows); err != nil {
		return identity.Container{}, fmt.Errorf("decode podman inspect output: %w", err)
	}
	if len(rows) == 0 {
		return identity.Container{}, fmt.Errorf("podman inspect returned no rows for %s", id)
	}

	row := rows[0]
	inspectID := row.ID
	if inspectID == "" {
		inspectID = row.UpperID
	}
	container := identity.Container{
		ID:         inspectID,
		Name:       strings.TrimPrefix(row.Name, "/"),
		PodID:      row.Pod,
		PID:        row.State.PID,
		CgroupPath: row.State.CgroupPath,
		StartedAt:  parsePodmanTime(row.State.StartedAt),
	}
	container.NetNSInode = namespaceInode(container.PID, "net")
	container.MountNSInode = namespaceInode(container.PID, "mnt")
	container.CgroupID = cgroupID(container.PID, container.CgroupPath)
	return container, nil
}

// cgroupID returns the cgroup-v2 directory inode for the container, which
// is the same value that BPF programs receive from
// `bpf_get_current_cgroup_id()`. Lookup proceeds in two stages:
//
//  1. If Podman reported a cgroup path, stat /sys/fs/cgroup/<path>.
//  2. Otherwise, parse /proc/<pid>/cgroup, take the unified
//     "0::/<path>" line, and stat /sys/fs/cgroup/<path>.
func cgroupID(pid int, reportedPath string) uint64 {
	const root = "/sys/fs/cgroup"

	if reportedPath != "" {
		if id := statInode(filepath.Join(root, reportedPath)); id != 0 {
			return id
		}
	}
	if pid <= 0 {
		return 0
	}

	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", pid))
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(data), "\n") {
		// cgroup-v2 lines have the form "0::/some/path".
		if !strings.HasPrefix(line, "0::") {
			continue
		}
		path := strings.TrimPrefix(line, "0::")
		path = strings.TrimSpace(path)
		if path == "" {
			continue
		}
		return statInode(filepath.Join(root, path))
	}
	return 0
}

type psRow struct {
	ID      string `json:"Id"`
	UpperID string `json:"ID"`
}

type inspectRow struct {
	ID      string `json:"Id"`
	UpperID string `json:"ID"`
	Name    string `json:"Name"`
	Pod     string `json:"Pod"`
	State   struct {
		PID        int    `json:"Pid"`
		CgroupPath string `json:"CgroupPath"`
		StartedAt  string `json:"StartedAt"`
	} `json:"State"`
}

func namespaceInode(pid int, namespace string) uint64 {
	if pid <= 0 {
		return 0
	}
	return statInode(fmt.Sprintf("/proc/%d/ns/%s", pid, namespace))
}

func statInode(path string) uint64 {
	info, err := os.Stat(path)
	if err != nil {
		return 0
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0
	}
	return stat.Ino
}

func parsePodmanTime(value string) time.Time {
	if value == "" {
		return time.Time{}
	}
	if parsed, err := time.Parse(time.RFC3339Nano, value); err == nil {
		return parsed
	}
	if unix, err := strconv.ParseInt(value, 10, 64); err == nil {
		return time.Unix(unix, 0)
	}
	return time.Time{}
}
