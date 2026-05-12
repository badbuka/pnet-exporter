package delays

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func writeSchedStat(t *testing.T, root string, pid int, content string) {
	t.Helper()
	dir := filepath.Join(root, fmt.Sprintf("%d", pid))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "schedstat"), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func writeStatFile(t *testing.T, root string, pid int, content string) {
	t.Helper()
	dir := filepath.Join(root, fmt.Sprintf("%d", pid))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "stat"), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestReadSchedStatParsesRunWait(t *testing.T) {
	root := t.TempDir()
	writeSchedStat(t, root, 100, "1000000 5000000 42\n")

	runWait, ioWait, err := readSchedStat(root, 100)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if runWait != 5_000_000 {
		t.Fatalf("runWaitNS: got %d, want 5000000", runWait)
	}
	if ioWait != 0 {
		t.Fatalf("ioWaitNS: got %d, want 0 (no stat file)", ioWait)
	}
}

func TestReadSchedStatWithBlkioTicks(t *testing.T) {
	root := t.TempDir()
	writeSchedStat(t, root, 200, "1000000 2000000 10\n")
	// After stripping pid and comm from /proc/<pid>/stat, the code calls
	// strings.Fields on the remainder. stats[0] = state, stats[39] =
	// delayacct_blkio_ticks. We append 39 zero-fields after "S", with the
	// last one (fields[38] → stats[39]) set to 100.
	fields := make([]string, 39)
	for i := range fields {
		fields[i] = "0"
	}
	fields[38] = "100" // stats[39] after splitting
	stat := "200 (myproc) S"
	for _, f := range fields {
		stat += " " + f
	}
	stat += "\n"
	writeStatFile(t, root, 200, stat)

	_, ioWait, err := readSchedStat(root, 200)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// 100 ticks * 10_000_000 ns/tick = 1_000_000_000 ns
	if ioWait != 100*10_000_000 {
		t.Fatalf("ioWaitNS: got %d, want %d", ioWait, 100*10_000_000)
	}
}

func TestReadSchedStatTooShort(t *testing.T) {
	root := t.TempDir()
	writeSchedStat(t, root, 300, "999\n")

	if _, _, err := readSchedStat(root, 300); err == nil {
		t.Fatal("expected error for one-field schedstat")
	}
}

func TestReadSchedStatMissingFile(t *testing.T) {
	root := t.TempDir()
	if _, _, err := readSchedStat(root, 999); err == nil {
		t.Fatal("expected error for non-existent schedstat file")
	}
}
