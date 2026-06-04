package resources

import (
	"testing"

	"pnet-exporter/internal/store"
)

func TestApplyCPUStat(t *testing.T) {
	data := "usage_usec 2000000\nuser_usec 1500000\nsystem_usec 500000\nnr_periods 100\nnr_throttled 7\nthrottled_usec 250000\n"
	var s store.ResourceUsageSample
	applyCPUStat(&s, data)

	if s.CPUUsageSeconds != 2.0 {
		t.Errorf("usage seconds = %v, want 2.0", s.CPUUsageSeconds)
	}
	if s.CPUUserSeconds != 1.5 {
		t.Errorf("user seconds = %v, want 1.5", s.CPUUserSeconds)
	}
	if s.CPUSystemSeconds != 0.5 {
		t.Errorf("system seconds = %v, want 0.5", s.CPUSystemSeconds)
	}
	if s.CPUPeriods != 100 {
		t.Errorf("periods = %v, want 100", s.CPUPeriods)
	}
	if s.CPUThrottledPeriods != 7 {
		t.Errorf("throttled periods = %v, want 7", s.CPUThrottledPeriods)
	}
	if s.CPUThrottledSeconds != 0.25 {
		t.Errorf("throttled seconds = %v, want 0.25", s.CPUThrottledSeconds)
	}
}

func TestApplyIOStatSumsDevices(t *testing.T) {
	data := "8:0 rbytes=1000 wbytes=2000 rios=10 wios=20 dbytes=0 dios=0\n253:1 rbytes=500 wbytes=100 rios=5 wios=1\n"
	var s store.ResourceUsageSample
	applyIOStat(&s, data)

	if s.IOReadBytes != 1500 {
		t.Errorf("read bytes = %v, want 1500", s.IOReadBytes)
	}
	if s.IOWrittenBytes != 2100 {
		t.Errorf("written bytes = %v, want 2100", s.IOWrittenBytes)
	}
	if s.IOReads != 15 {
		t.Errorf("reads = %v, want 15", s.IOReads)
	}
	if s.IOWrites != 21 {
		t.Errorf("writes = %v, want 21", s.IOWrites)
	}
}

func TestParsePressure(t *testing.T) {
	data := "some avg10=0.00 avg60=0.10 avg300=0.05 total=2000000\nfull avg10=0.00 avg60=0.00 avg300=0.00 total=1000000\n"
	some, full, ok := parsePressure(data)
	if !ok {
		t.Fatal("expected ok")
	}
	if some != 2.0 {
		t.Errorf("some = %v, want 2.0", some)
	}
	if full != 1.0 {
		t.Errorf("full = %v, want 1.0", full)
	}
}

func TestParsePressureCPUSomeOnly(t *testing.T) {
	// Older kernels expose only a "some" line for cpu.pressure.
	data := "some avg10=0.00 avg60=0.00 avg300=0.00 total=500000\n"
	some, full, ok := parsePressure(data)
	if !ok {
		t.Fatal("expected ok")
	}
	if some != 0.5 {
		t.Errorf("some = %v, want 0.5", some)
	}
	if full != 0 {
		t.Errorf("full = %v, want 0", full)
	}
}

func TestParseMemoryMax(t *testing.T) {
	if _, ok := parseMemoryMax("max\n"); ok {
		t.Error("expected max to report no limit")
	}
	v, ok := parseMemoryMax("104857600\n")
	if !ok || v != 104857600 {
		t.Errorf("parseMemoryMax = %v,%v want 104857600,true", v, ok)
	}
}
