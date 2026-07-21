package node

import (
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

// TestCollectorCollect drives a full scrape against a fake /proc and
// verifies the exported metric names, labels, and unit conversions.
func TestCollectorCollect(t *testing.T) {
	root := t.TempDir()
	write := func(name, contents string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(filepath.Join(root, name)), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, name), []byte(contents), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("stat", "cpu  100 0 200 400 0 0 0 0 0 0\n")
	write("meminfo", "MemTotal:       1024 kB\nMemAvailable:   512 kB\n")
	write("uptime", "1000.00 2000.00\n")
	write("diskstats", "   8       0 sda 10 0 100 0 20 0 200 0 0 0 0 0\n")
	write("net/dev", "Inter-|   Receive  |  Transmit\n"+
		" face |bytes packets errs drop fifo frame compressed multicast|bytes packets errs drop fifo colls carrier compressed\n"+
		" eth0: 1000 10 1 0 0 0 0 0 2000 20 2 0 0 0 0 0\n")

	reg := prometheus.NewRegistry()
	reg.MustRegister(NewCollector(root, "testhost", slog.Default()))

	expected := `
# HELP node_cpu_seconds_total Aggregate /proc/stat cpu times in seconds, split by mode.
# TYPE node_cpu_seconds_total counter
node_cpu_seconds_total{mode="idle",node_hostname="testhost"} 4
node_cpu_seconds_total{mode="iowait",node_hostname="testhost"} 0
node_cpu_seconds_total{mode="irq",node_hostname="testhost"} 0
node_cpu_seconds_total{mode="nice",node_hostname="testhost"} 0
node_cpu_seconds_total{mode="softirq",node_hostname="testhost"} 0
node_cpu_seconds_total{mode="steal",node_hostname="testhost"} 0
node_cpu_seconds_total{mode="system",node_hostname="testhost"} 2
node_cpu_seconds_total{mode="user",node_hostname="testhost"} 1
# HELP node_disk_read_bytes_total Total bytes read per disk device.
# TYPE node_disk_read_bytes_total counter
node_disk_read_bytes_total{device="sda",node_hostname="testhost"} 51200
# HELP node_memory_available_bytes Estimated available memory for new allocations.
# TYPE node_memory_available_bytes gauge
node_memory_available_bytes{node_hostname="testhost"} 524288
# HELP node_memory_total_bytes Total physical memory in bytes.
# TYPE node_memory_total_bytes gauge
node_memory_total_bytes{node_hostname="testhost"} 1.048576e+06
# HELP node_network_receive_bytes_total Total bytes received per network interface.
# TYPE node_network_receive_bytes_total counter
node_network_receive_bytes_total{interface="eth0",node_hostname="testhost"} 1000
# HELP node_network_transmit_errors_total Total transmit errors per network interface.
# TYPE node_network_transmit_errors_total counter
node_network_transmit_errors_total{interface="eth0",node_hostname="testhost"} 2
# HELP node_uptime_seconds Time since the kernel finished booting.
# TYPE node_uptime_seconds gauge
node_uptime_seconds{node_hostname="testhost"} 1000
`
	err := testutil.GatherAndCompare(reg, strings.NewReader(expected),
		"node_cpu_seconds_total",
		"node_memory_total_bytes",
		"node_memory_available_bytes",
		"node_uptime_seconds",
		"node_disk_read_bytes_total",
		"node_network_receive_bytes_total",
		"node_network_transmit_errors_total",
	)
	if err != nil {
		t.Fatal(err)
	}
}

// TestCollectorMissingProc emits nothing and must not panic when /proc
// files are absent (e.g. wrong PNET_PROC_FS).
func TestCollectorMissingProc(t *testing.T) {
	reg := prometheus.NewRegistry()
	reg.MustRegister(NewCollector(filepath.Join(t.TempDir(), "nope"), "testhost", slog.Default()))
	families, err := reg.Gather()
	if err != nil {
		t.Fatal(err)
	}
	if len(families) != 0 {
		t.Fatalf("expected no metrics from missing /proc, got %d families", len(families))
	}
}
