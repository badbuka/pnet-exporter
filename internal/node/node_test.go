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

func TestUptime(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "uptime"), []byte("12345.67 89012.34\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	up, err := Uptime(root)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if up != 12345.67 {
		t.Fatalf("expected 12345.67, got %f", up)
	}
}

func TestUptimeEmpty(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "uptime"), []byte(""), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Uptime(root); err == nil {
		t.Fatal("expected error for empty uptime file")
	}
}

func TestReadNetInterfaceCounters(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "net"), 0o755); err != nil {
		t.Fatal(err)
	}
	contents := "Inter-|   Receive                                                |  Transmit\n" +
		" face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed\n" +
		"    lo:    1000      10    0    0    0     0          0         0     1000      10    0    0    0     0       0          0\n" +
		"  eth0:  999000    5000    1    0    0     0          0         0   555000    3000    2    0    0     0       0          0\n"
	if err := os.WriteFile(filepath.Join(root, "net", "dev"), []byte(contents), 0o644); err != nil {
		t.Fatal(err)
	}
	nics, err := ReadNetInterfaceCounters(root)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if len(nics) != 2 {
		t.Fatalf("expected 2 interfaces, got %d", len(nics))
	}
	for _, nic := range nics {
		switch nic.Interface {
		case "lo":
			if nic.ReceivedBytes != 1000 {
				t.Fatalf("lo ReceivedBytes: got %d, want 1000", nic.ReceivedBytes)
			}
		case "eth0":
			if nic.ReceivedErrors != 1 {
				t.Fatalf("eth0 ReceivedErrors: got %d, want 1", nic.ReceivedErrors)
			}
			if nic.TransmitErrors != 2 {
				t.Fatalf("eth0 TransmitErrors: got %d, want 2", nic.TransmitErrors)
			}
		default:
			t.Fatalf("unexpected interface: %q", nic.Interface)
		}
	}
}

func TestReadNetInterfaceCountersSkipsShort(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "net"), 0o755); err != nil {
		t.Fatal(err)
	}
	contents := "Inter-|   Receive                                                |  Transmit\n" +
		" face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed\n"
	if err := os.WriteFile(filepath.Join(root, "net", "dev"), []byte(contents), 0o644); err != nil {
		t.Fatal(err)
	}
	nics, err := ReadNetInterfaceCounters(root)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if len(nics) != 0 {
		t.Fatalf("expected empty slice for header-only file, got %d", len(nics))
	}
}
