package discovery

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"pnet-exporter/internal/identity"
)

// containerCgroupRe matches the container cgroup marker in a
// /proc/<pid>/cgroup line for both supported runtimes. Container IDs are 64
// lowercase hex characters. Podman appears as `libpod-<id>.scope` (systemd)
// or `libpod-<id>` (cgroupfs); Docker appears as `docker-<id>.scope`
// (systemd driver) or `/docker/<id>` (cgroupfs driver). The conmon helper
// (`libpod-conmon-<id>.scope`) never matches because "conmon" is not a
// 64-char hex run.
var containerCgroupRe = regexp.MustCompile(`(?:libpod-|docker[-/])([0-9a-f]{64})`)

// podmanAPIPath is the libpod container-list path. Podman keeps the v4 path
// stable for backward compatibility even on newer daemons.
const podmanAPIPath = "/v4.0.0/libpod/containers/json"

// dockerAPIPath is the Docker Engine API container-list path. The version is
// pinned conservatively; the daemon maintains backward compatibility for this
// endpoint across releases.
const dockerAPIPath = "/v1.41/containers/json"

// socketDialTimeout bounds both the connect and overall request time when
// talking to a runtime socket. Unreachable rootless or absent Docker sockets
// must fail fast so a single discovery tick stays cheap.
const socketDialTimeout = 3 * time.Second

// socketContextKey carries the target unix socket path through the request
// context so a single http.Client can fan out across every candidate socket.
type socketContextKey struct{}

type Discoverer struct {
	sysFS           string
	procFS          string
	rootSocket      string
	userSocketsGlob string
	dockerSocket    string
	httpClient      *http.Client
	logger          *slog.Logger
}

// NewDiscoverer builds a discoverer that treats the host /proc as the source
// of truth for which containers exist and queries every reachable runtime
// socket (Podman libpod sockets and the Docker Engine socket) only to enrich
// names and pod IDs.
func NewDiscoverer(socket, userSocketsGlob, dockerSocket, procFS, sysFS string, logger *slog.Logger) *Discoverer {
	return &Discoverer{
		sysFS:           sysFS,
		procFS:          procFS,
		rootSocket:      socket,
		userSocketsGlob: userSocketsGlob,
		dockerSocket:    dockerSocket,
		httpClient:      newUnixClient(socketDialTimeout),
		logger:          logger,
	}
}

// List scans /proc for container cgroups, enriches the results with names and
// pod IDs from every reachable runtime socket, and returns the merged set. It
// never fails when /proc is empty or no socket responds; such containers
// simply surface without a name and fall back to their ID in metric labels.
func (d *Discoverer) List(ctx context.Context) ([]identity.Container, error) {
	scanned := d.scanProc()
	names := d.enrich(ctx)

	containers := make([]identity.Container, 0, len(scanned))
	for id, container := range scanned {
		if meta, ok := names[id]; ok {
			container.Name = meta.Name
			container.PodID = meta.Pod
		}
		containers = append(containers, container)
	}
	return containers, nil
}

// scanProc walks ${procFS}/<pid>/cgroup for every process and groups the
// discovered containers by their 64-char ID. The lowest PID per container
// wins, which is the most stable representative of the container's init
// process for namespace/cgroup attribution.
func (d *Discoverer) scanProc() map[string]identity.Container {
	entries, err := os.ReadDir(d.procFS)
	if err != nil {
		d.logger.Warn("scan procfs failed", "procfs", d.procFS, "error", err)
		return nil
	}

	lowestPID := make(map[string]int)
	cgroupPaths := make(map[string]string)
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(entry.Name())
		if err != nil || pid <= 0 {
			continue
		}
		data, err := os.ReadFile(filepath.Join(d.procFS, entry.Name(), "cgroup"))
		if err != nil {
			continue
		}
		id, unifiedPath := parseCgroup(string(data))
		if id == "" {
			continue
		}
		if cur, ok := lowestPID[id]; !ok || pid < cur {
			lowestPID[id] = pid
			cgroupPaths[id] = unifiedPath
		}
	}

	containers := make(map[string]identity.Container, len(lowestPID))
	for id, pid := range lowestPID {
		cgroupPath := cgroupPaths[id]
		container := identity.Container{
			ID:           id,
			PID:          pid,
			CgroupPath:   cgroupPath,
			CgroupID:     d.cgroupID(cgroupPath),
			NetNSInode:   d.namespaceInode(pid, "net"),
			MountNSInode: d.namespaceInode(pid, "mnt"),
			StartedAt:    d.cgroupModTime(cgroupPath),
		}
		containers[id] = container
	}
	return containers
}

// parseCgroup extracts the container ID and the cgroup-v2 unified path from
// the contents of a /proc/<pid>/cgroup file. The ID is taken from any line
// bearing a recognized runtime marker; the unified path is the "0::" line,
// used to stat the cgroup directory inode that BPF programs report.
func parseCgroup(content string) (id, unifiedPath string) {
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if id == "" {
			if m := containerCgroupRe.FindStringSubmatch(line); m != nil {
				id = m[1]
			}
		}
		if strings.HasPrefix(line, "0::") {
			unifiedPath = strings.TrimSpace(strings.TrimPrefix(line, "0::"))
		}
	}
	return id, unifiedPath
}

// cgroupID returns the cgroup-v2 directory inode for the unified path, which
// equals the value BPF programs receive from bpf_get_current_cgroup_id().
func (d *Discoverer) cgroupID(unifiedPath string) uint64 {
	if unifiedPath == "" {
		return 0
	}
	return statInode(filepath.Join(d.sysFS, "fs", "cgroup", unifiedPath))
}

// cgroupModTime uses the cgroup directory mtime as a stand-in for the
// container start time. It avoids parsing /proc/<pid>/stat clock ticks and is
// good enough for ordering and freshness.
func (d *Discoverer) cgroupModTime(unifiedPath string) time.Time {
	if unifiedPath == "" {
		return time.Time{}
	}
	info, err := os.Stat(filepath.Join(d.sysFS, "fs", "cgroup", unifiedPath))
	if err != nil {
		return time.Time{}
	}
	return info.ModTime()
}

func (d *Discoverer) namespaceInode(pid int, namespace string) uint64 {
	if pid <= 0 {
		return 0
	}
	return statInode(filepath.Join(d.procFS, strconv.Itoa(pid), "ns", namespace))
}

// enrichment holds the human-facing metadata a runtime socket can add to a
// container that /proc only knows by ID.
type enrichment struct {
	Name string
	Pod  string
}

// enrichSource is a single socket to probe together with the runtime API path
// used to list its containers.
type enrichSource struct {
	socket  string
	apiPath string
}

// enrich queries every candidate runtime socket and merges their container
// listings into a map keyed by full container ID. Sockets that are missing or
// unreachable are logged at debug and skipped.
func (d *Discoverer) enrich(ctx context.Context) map[string]enrichment {
	sources := d.enrichmentSources()
	perSocket := make([][]containerRow, 0, len(sources))
	for _, src := range sources {
		rows, err := d.querySocket(ctx, src.socket, src.apiPath)
		if err != nil {
			d.logger.Debug("runtime socket query failed", "socket", src.socket, "error", err)
			continue
		}
		d.logger.Debug("runtime socket enriched", "socket", src.socket, "containers", len(rows))
		perSocket = append(perSocket, rows)
	}
	return mergeEnrichment(perSocket)
}

// enrichmentSources returns the deduplicated list of sockets to probe: the
// configured root Podman socket, every match of the user sockets glob, and
// the Docker Engine socket. Each source carries the API path for its runtime.
func (d *Discoverer) enrichmentSources() []enrichSource {
	seen := make(map[string]struct{})
	var sources []enrichSource
	add := func(path, apiPath string) {
		if path == "" {
			return
		}
		if _, ok := seen[path]; ok {
			return
		}
		seen[path] = struct{}{}
		sources = append(sources, enrichSource{socket: path, apiPath: apiPath})
	}

	add(d.rootSocket, podmanAPIPath)
	if d.userSocketsGlob != "" {
		matches, err := filepath.Glob(d.userSocketsGlob)
		if err != nil {
			d.logger.Debug("podman user socket glob failed", "glob", d.userSocketsGlob, "error", err)
		}
		for _, match := range matches {
			add(match, podmanAPIPath)
		}
	}
	add(d.dockerSocket, dockerAPIPath)
	return sources
}

// querySocket fetches the running container list from a single runtime socket
// over HTTP-over-Unix. The socket path travels via the request context so the
// shared http.Client can target any socket.
func (d *Discoverer) querySocket(ctx context.Context, socket, apiPath string) ([]containerRow, error) {
	ctx = context.WithValue(ctx, socketContextKey{}, socket)
	url := "http://runtime" + apiPath
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := d.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("runtime api returned %s", resp.Status)
	}

	var rows []containerRow
	if err := json.NewDecoder(resp.Body).Decode(&rows); err != nil {
		return nil, fmt.Errorf("decode runtime api response: %w", err)
	}
	return rows, nil
}

// mergeEnrichment folds per-socket container listings into a single map keyed
// by full container ID. When the same ID is reported by more than one socket
// the first occurrence wins.
func mergeEnrichment(perSocket [][]containerRow) map[string]enrichment {
	out := make(map[string]enrichment)
	for _, rows := range perSocket {
		for _, row := range rows {
			id := row.ID
			if id == "" {
				continue
			}
			if _, exists := out[id]; exists {
				continue
			}
			out[id] = enrichment{Name: row.name(), Pod: row.Pod}
		}
	}
	return out
}

// containerRow mirrors the subset of the runtime container-list payload that
// we consume. It fits both Podman's libpod ListContainer response and the
// Docker Engine API; Docker simply omits the Pod field.
type containerRow struct {
	ID    string   `json:"Id"`
	Names []string `json:"Names"`
	Pod   string   `json:"Pod"`
}

func (r containerRow) name() string {
	if len(r.Names) > 0 {
		return strings.TrimPrefix(r.Names[0], "/")
	}
	return ""
}

// newUnixClient builds an http.Client whose transport dials the unix socket
// named in the request context, allowing one client to serve every candidate
// socket.
func newUnixClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				socket, _ := ctx.Value(socketContextKey{}).(string)
				if socket == "" {
					return nil, errors.New("no runtime socket in request context")
				}
				var dialer net.Dialer
				return dialer.DialContext(ctx, "unix", socket)
			},
		},
	}
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
