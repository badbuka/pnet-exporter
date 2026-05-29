package podman

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

const (
	idA = "1111111111111111111111111111111111111111111111111111111111111111"
	idB = "2222222222222222222222222222222222222222222222222222222222222222"
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

func TestMergeEnrichmentNoSockets(t *testing.T) {
	if got := mergeEnrichment(nil); len(got) != 0 {
		t.Fatalf("expected empty enrichment, got %#v", got)
	}
}

func TestListMergesScanAndEnrichment(t *testing.T) {
	procFS := t.TempDir()
	writeProcCgroup(t, procFS, 100, "0::/machine.slice/libpod-"+idA+".scope/container")
	writeProcCgroup(t, procFS, 200, "0::/machine.slice/libpod-"+idB+".scope/container")

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
	// An empty glob and an unreachable root socket keep enrichment a no-op.
	return NewDiscoverer(filepath.Join(sysFS, "no-such.sock"), "", procFS, sysFS, logger)
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
