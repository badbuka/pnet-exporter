package discovery

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

const (
	idA = "1111111111111111111111111111111111111111111111111111111111111111"
	idB = "2222222222222222222222222222222222222222222222222222222222222222"
	idC = "3333333333333333333333333333333333333333333333333333333333333333"
	idD = "4444444444444444444444444444444444444444444444444444444444444444"
)

func TestParseCgroup(t *testing.T) {
	tests := []struct {
		name      string
		content   string
		wantID    string
		wantUnifd string
	}{
		{
			name:      "rootful systemd scope",
			content:   "0::/machine.slice/libpod-" + idA + ".scope/container\n",
			wantID:    idA,
			wantUnifd: "/machine.slice/libpod-" + idA + ".scope/container",
		},
		{
			name: "rootless user slice",
			content: "0::/user.slice/user-1000.slice/user@1000.service/user.slice/" +
				"libpod-" + idA + ".scope/container\n",
			wantID:    idA,
			wantUnifd: "/user.slice/user-1000.slice/user@1000.service/user.slice/libpod-" + idA + ".scope/container",
		},
		{
			name:      "cgroupfs layout without scope",
			content:   "0::/libpod_parent/libpod-" + idA + "\n",
			wantID:    idA,
			wantUnifd: "/libpod_parent/libpod-" + idA,
		},
		{
			name:      "docker systemd scope",
			content:   "0::/system.slice/docker-" + idA + ".scope\n",
			wantID:    idA,
			wantUnifd: "/system.slice/docker-" + idA + ".scope",
		},
		{
			name:      "docker cgroupfs layout",
			content:   "0::/docker/" + idA + "\n",
			wantID:    idA,
			wantUnifd: "/docker/" + idA,
		},
		{
			name: "hybrid v1 lines plus unified",
			content: "12:pids:/machine.slice/libpod-" + idA + ".scope\n" +
				"1:name=systemd:/machine.slice/libpod-" + idA + ".scope\n" +
				"0::/machine.slice/libpod-" + idA + ".scope/container\n",
			wantID:    idA,
			wantUnifd: "/machine.slice/libpod-" + idA + ".scope/container",
		},
		{
			name:      "conmon helper is not a container",
			content:   "0::/machine.slice/libpod-conmon-" + idA + ".scope\n",
			wantID:    "",
			wantUnifd: "/machine.slice/libpod-conmon-" + idA + ".scope",
		},
		{
			name:      "non-container process",
			content:   "0::/system.slice/sshd.service\n",
			wantID:    "",
			wantUnifd: "/system.slice/sshd.service",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			id, unified := parseCgroup(tt.content)
			if id != tt.wantID {
				t.Errorf("id = %q, want %q", id, tt.wantID)
			}
			if unified != tt.wantUnifd {
				t.Errorf("unified = %q, want %q", unified, tt.wantUnifd)
			}
		})
	}
}

func TestScanProcLowestPIDWins(t *testing.T) {
	procFS := t.TempDir()
	// Two PIDs for container A (lowest 17 should win), one for B, plus noise.
	writeProcCgroup(t, procFS, 42, "0::/machine.slice/libpod-"+idA+".scope/container")
	writeProcCgroup(t, procFS, 17, "0::/machine.slice/libpod-"+idA+".scope/container")
	writeProcCgroup(t, procFS, 9, "0::/user.slice/user-1000.slice/libpod-"+idB+".scope/container")
	writeProcCgroup(t, procFS, 3, "0::/system.slice/sshd.service")
	// Non-numeric proc entry must be ignored.
	if err := os.MkdirAll(filepath.Join(procFS, "self"), 0o755); err != nil {
		t.Fatal(err)
	}

	d := newTestDiscoverer(procFS, t.TempDir())
	got := d.scanProc()

	if len(got) != 2 {
		t.Fatalf("expected 2 containers, got %d: %#v", len(got), got)
	}
	if c, ok := got[idA]; !ok || c.PID != 17 {
		t.Fatalf("container A PID = %d (ok=%v), want 17", c.PID, ok)
	}
	if c, ok := got[idB]; !ok || c.PID != 9 {
		t.Fatalf("container B PID = %d (ok=%v), want 9", c.PID, ok)
	}
	if got[idA].CgroupPath != "/machine.slice/libpod-"+idA+".scope/container" {
		t.Fatalf("unexpected cgroup path: %q", got[idA].CgroupPath)
	}
}

func TestScanProcMixedRuntimes(t *testing.T) {
	procFS := t.TempDir()
	// Podman (systemd + cgroupfs) alongside Docker (systemd + cgroupfs).
	writeProcCgroup(t, procFS, 10, "0::/machine.slice/libpod-"+idA+".scope/container")
	writeProcCgroup(t, procFS, 20, "0::/libpod_parent/libpod-"+idB)
	writeProcCgroup(t, procFS, 30, "0::/system.slice/docker-"+idC+".scope")
	writeProcCgroup(t, procFS, 40, "0::/docker/"+idD)

	d := newTestDiscoverer(procFS, t.TempDir())
	got := d.scanProc()

	if len(got) != 4 {
		t.Fatalf("expected 4 containers, got %d: %#v", len(got), got)
	}
	for _, id := range []string{idA, idB, idC, idD} {
		if _, ok := got[id]; !ok {
			t.Errorf("missing container %q", id)
		}
	}
	if got[idC].CgroupPath != "/system.slice/docker-"+idC+".scope" {
		t.Errorf("unexpected docker systemd cgroup path: %q", got[idC].CgroupPath)
	}
	if got[idD].CgroupPath != "/docker/"+idD {
		t.Errorf("unexpected docker cgroupfs path: %q", got[idD].CgroupPath)
	}
}

func TestScanProcEmpty(t *testing.T) {
	d := newTestDiscoverer(t.TempDir(), t.TempDir())
	if got := d.scanProc(); len(got) != 0 {
		t.Fatalf("expected no containers, got %d", len(got))
	}
}

func TestMergeEnrichment(t *testing.T) {
	socketRootful := []containerRow{
		{ID: idA, Names: []string{"/web"}, Pod: "pod-1"},
	}
	socketRootless := []containerRow{
		{ID: idB, Names: []string{"db"}},
		// Conflicting name for idA: first socket wins.
		{ID: idA, Names: []string{"web-rootless"}, Pod: "pod-z"},
		// Empty ID is dropped.
		{ID: "", Names: []string{"ghost"}},
	}

	got := mergeEnrichment([][]containerRow{socketRootful, socketRootless})

	if len(got) != 2 {
		t.Fatalf("expected 2 enrichments, got %d: %#v", len(got), got)
	}
	if got[idA].Name != "web" || got[idA].Pod != "pod-1" {
		t.Errorf("idA = %#v, want first-socket values (web/pod-1)", got[idA])
	}
	if got[idB].Name != "db" || got[idB].Pod != "" {
		t.Errorf("idB = %#v, want db/empty", got[idB])
	}
}

func TestMergeEnrichmentDockerRow(t *testing.T) {
	// Docker's containers/json reports a leading-slash name and no Pod.
	dockerSocket := []containerRow{
		{ID: idC, Names: []string{"/nginx"}},
	}
	got := mergeEnrichment([][]containerRow{dockerSocket})
	if len(got) != 1 {
		t.Fatalf("expected 1 enrichment, got %d: %#v", len(got), got)
	}
	if got[idC].Name != "nginx" || got[idC].Pod != "" {
		t.Errorf("idC = %#v, want nginx/empty", got[idC])
	}
}

func TestMergeEnrichmentNoSockets(t *testing.T) {
	if got := mergeEnrichment(nil); len(got) != 0 {
		t.Fatalf("expected empty enrichment, got %#v", got)
	}
}

func TestEnrichmentSources(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	d := NewDiscoverer("/run/podman/podman.sock", "", "/var/run/docker.sock", t.TempDir(), t.TempDir(), logger)

	sources := d.enrichmentSources()
	if len(sources) != 2 {
		t.Fatalf("expected 2 sources, got %d: %#v", len(sources), sources)
	}
	if sources[0].socket != "/run/podman/podman.sock" || sources[0].apiPath != podmanAPIPath {
		t.Errorf("podman source = %#v", sources[0])
	}
	if sources[1].socket != "/var/run/docker.sock" || sources[1].apiPath != dockerAPIPath {
		t.Errorf("docker source = %#v", sources[1])
	}
}

func TestListMergesScanAndEnrichment(t *testing.T) {
	procFS := t.TempDir()
	writeProcCgroup(t, procFS, 100, "0::/machine.slice/libpod-"+idA+".scope/container")
	writeProcCgroup(t, procFS, 200, "0::/system.slice/docker-"+idB+".scope")

	d := newTestDiscoverer(procFS, t.TempDir())
	// No reachable sockets, so names stay empty but containers still surface.
	got, err := d.List(t.Context())
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 containers, got %d", len(got))
	}
	for _, c := range got {
		if c.Name != "" {
			t.Errorf("expected empty name without a socket, got %q", c.Name)
		}
		if c.ID != idA && c.ID != idB {
			t.Errorf("unexpected container id %q", c.ID)
		}
	}
}

func newTestDiscoverer(procFS, sysFS string) *Discoverer {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	// Empty globs and unreachable sockets keep enrichment a no-op.
	return NewDiscoverer(filepath.Join(sysFS, "no-such.sock"), "", filepath.Join(sysFS, "no-docker.sock"), procFS, sysFS, logger)
}

func writeProcCgroup(t *testing.T, procFS string, pid int, content string) {
	t.Helper()
	dir := filepath.Join(procFS, strconv.Itoa(pid))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "cgroup"), []byte(content+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
}

// serveRuntimeSocket starts an HTTP-over-unix fake runtime returning the
// given container rows as JSON, and returns the socket path.
func serveRuntimeSocket(t *testing.T, rows string) string {
	t.Helper()
	socket := filepath.Join(os.TempDir(), "pnet-test-"+strconv.Itoa(os.Getpid())+strconv.Itoa(int(time.Now().UnixNano()%1e6))+".sock")
	t.Cleanup(func() { _ = os.Remove(socket) })
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		_ = http.Serve(listener, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(rows))
		}))
	}()
	return socket
}

// TestQuerySocketHitsDistinctRuntimes guards the DisableKeepAlives fix:
// two sequential queries against different unix sockets must each reach
// their own runtime rather than reusing the first connection.
func TestQuerySocketHitsDistinctRuntimes(t *testing.T) {
	socketA := serveRuntimeSocket(t, `[{"Id":"aaa","Names":["/web-a"]}]`)
	socketB := serveRuntimeSocket(t, `[{"Id":"bbb","Names":["/web-b"]}]`)

	d := &Discoverer{httpClient: newUnixClient(5 * time.Second), logger: slog.Default()}

	rowsA, err := d.querySocket(context.Background(), socketA, "/v4.0.0/libpod/containers/json")
	if err != nil {
		t.Fatalf("query A: %v", err)
	}
	rowsB, err := d.querySocket(context.Background(), socketB, "/v4.0.0/libpod/containers/json")
	if err != nil {
		t.Fatalf("query B: %v", err)
	}
	if len(rowsA) != 1 || rowsA[0].ID != "aaa" {
		t.Fatalf("rows A: %#v", rowsA)
	}
	if len(rowsB) != 1 || rowsB[0].ID != "bbb" {
		t.Fatalf("rows B: %#v (keep-alive reuse hit the wrong runtime)", rowsB)
	}
}

func TestQuerySocketMissingSocket(t *testing.T) {
	d := &Discoverer{httpClient: newUnixClient(500 * time.Millisecond), logger: slog.Default()}
	if _, err := d.querySocket(context.Background(), filepath.Join(t.TempDir(), "nope.sock"), "/x"); err == nil {
		t.Fatal("expected error for missing socket")
	}
}
