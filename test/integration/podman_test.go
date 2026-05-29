//go:build integration

package integration

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"pnet-exporter/internal/podman"
)

// TestDiscovererListAgainstProcFixture exercises the /proc-scanning discovery
// path against a synthetic procfs tree, with no Podman socket reachable. It
// asserts that containers are surfaced purely from cgroup data, which is the
// behaviour the exporter relies on for rootless users whose socket may be
// absent.
func TestDiscovererListAgainstProcFixture(t *testing.T) {
	const id = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"

	procFS := t.TempDir()
	pidDir := filepath.Join(procFS, "4242")
	if err := os.MkdirAll(pidDir, 0o755); err != nil {
		t.Fatal(err)
	}
	cgroup := "0::/machine.slice/libpod-" + id + ".scope/container\n"
	if err := os.WriteFile(filepath.Join(pidDir, "cgroup"), []byte(cgroup), 0o644); err != nil {
		t.Fatal(err)
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	// Unreachable socket + empty glob: enrichment is a no-op, /proc is truth.
	d := podman.NewDiscoverer(filepath.Join(t.TempDir(), "missing.sock"), "", procFS, t.TempDir(), logger)

	containers, err := d.List(t.Context())
	if err != nil {
		t.Fatalf("List returned error: %v", err)
	}
	if len(containers) != 1 {
		t.Fatalf("expected 1 container from fixture, got %d", len(containers))
	}
	got := containers[0]
	if got.ID != id {
		t.Fatalf("container ID = %q, want %q", got.ID, id)
	}
	if got.PID != 4242 {
		t.Fatalf("container PID = %d, want 4242", got.PID)
	}
	if got.CgroupPath != "/machine.slice/libpod-"+id+".scope/container" {
		t.Fatalf("unexpected cgroup path: %q", got.CgroupPath)
	}
}

// TestHostProcIsReadable is a light sanity check that the real procfs exists
// on the host running the integration suite, since discovery depends on it.
func TestHostProcIsReadable(t *testing.T) {
	if _, err := os.Stat("/proc/self/cgroup"); err != nil {
		t.Skipf("/proc not available: %v", err)
	}
}
