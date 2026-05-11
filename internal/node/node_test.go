package node

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReadCPUTimes(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "stat"), []byte(
		"cpu  100 200 300 400 500 600 700 800 0 0\n"+
			"cpu0 50 100 150 200 250 300 350 400\n",
	), 0o644); err != nil {
		t.Fatal(err)
	}
	cpu, err := ReadCPUTimes(root)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if cpu.User != 100 || cpu.System != 300 || cpu.Idle != 400 || cpu.Steal != 800 {
		t.Fatalf("unexpected cpu: %+v", cpu)
	}
}

func TestReadMemory(t *testing.T) {
	root := t.TempDir()
	contents := "MemTotal:        16334376 kB\n" +
		"MemFree:          1234567 kB\n" +
		"MemAvailable:     8765432 kB\n" +
		"Buffers:           100000 kB\n" +
		"Cached:           2000000 kB\n"
	if err := os.WriteFile(filepath.Join(root, "meminfo"), []byte(contents), 0o644); err != nil {
		t.Fatal(err)
	}
	mem, err := ReadMemory(root)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if mem.TotalBytes == 0 || mem.AvailableBytes == 0 {
		t.Fatalf("unexpected memory: %+v", mem)
	}
	if mem.TotalBytes != 16334376*1024 {
		t.Fatalf("total bytes mismatch: %d", mem.TotalBytes)
	}
}

func TestReadDiskCountersSkipsLoop(t *testing.T) {
	root := t.TempDir()
	contents := "   7       0 loop0 1 2 3 4 5 6 7 8 9 10 11\n" +
		"   8       0 sda 100 0 200 0 300 0 400 0 0 0 0 0 0 0 0\n"
	if err := os.WriteFile(filepath.Join(root, "diskstats"), []byte(contents), 0o644); err != nil {
		t.Fatal(err)
	}
	disks, err := ReadDiskCounters(root)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if len(disks) != 1 || disks[0].Device != "sda" {
		t.Fatalf("unexpected disks: %+v", disks)
	}
}
