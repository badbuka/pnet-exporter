package ebpf

import (
	"encoding/binary"
	"testing"

	"pnet-exporter/internal/store"
)

func TestDecodeTCPEventIPv4(t *testing.T) {
	buf := make([]byte, tcpEventWireSize)
	buf[0] = byte(EventTCPSuccessfulConnect)
	binary.LittleEndian.PutUint64(buf[8:16], 0xCAFE)
	binary.LittleEndian.PutUint32(buf[16:20], 4242)
	// destination 10.0.0.1, port 8080, family AF_INET (2)
	buf[36] = 10
	buf[37] = 0
	buf[38] = 0
	buf[39] = 1
	binary.LittleEndian.PutUint16(buf[54:56], 8080)
	binary.LittleEndian.PutUint16(buf[56:58], familyIPv4)
	binary.LittleEndian.PutUint64(buf[64:72], 1)

	event, err := DecodeTCPEvent(buf)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if event.Kind != EventTCPSuccessfulConnect {
		t.Fatalf("kind: got %d", event.Kind)
	}
	if event.CgroupID != 0xCAFE || event.PID != 4242 {
		t.Fatalf("identity: got cgroup=%x pid=%d", event.CgroupID, event.PID)
	}
	if got := event.Tuple.Destination(); got != "10.0.0.1:8080" {
		t.Fatalf("destination: got %q", got)
	}
}

func TestDecodeTCPEventTruncated(t *testing.T) {
	if _, err := DecodeTCPEvent(make([]byte, 10)); err == nil {
		t.Fatal("expected error on truncated event")
	}
}

func TestDecodeNATEvent(t *testing.T) {
	buf := make([]byte, natEventWireSize)
	buf[0] = byte(EventConntrackNAT)
	// orig destination 10.0.0.1:5432
	buf[36] = 10
	buf[37] = 0
	buf[38] = 0
	buf[39] = 1
	binary.LittleEndian.PutUint16(buf[54:56], 5432)
	binary.LittleEndian.PutUint16(buf[56:58], familyIPv4)
	// reply source 172.20.0.5:5432 (post-DNAT actual destination)
	buf[58+0] = 172
	buf[58+1] = 20
	buf[58+2] = 0
	buf[58+3] = 5
	binary.LittleEndian.PutUint16(buf[58+32:58+34], 5432)
	binary.LittleEndian.PutUint16(buf[58+36:58+38], familyIPv4)

	event, err := DecodeNATEvent(buf)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got := event.Orig.Destination(); got != "10.0.0.1:5432" {
		t.Fatalf("orig destination: got %q", got)
	}
	if got := event.Reply.Source(); got != "172.20.0.5:5432" {
		t.Fatalf("reply source: got %q", got)
	}
}

func TestDecodeOOMEvent(t *testing.T) {
	buf := make([]byte, oomEventWireSize)
	buf[0] = byte(EventOOM)
	binary.LittleEndian.PutUint64(buf[8:16], 0xC0FE)
	binary.LittleEndian.PutUint32(buf[16:20], 100)
	binary.LittleEndian.PutUint32(buf[20:24], 200)

	event, err := DecodeOOMEvent(buf)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if event.CgroupID != 0xC0FE || event.PID != 100 || event.VictimPID != 200 {
		t.Fatalf("unexpected oom event %+v", event)
	}
}

func TestToStoreEventActualDestination(t *testing.T) {
	tcp := TCPEvent{Kind: EventTCPSuccessfulConnect}
	tcp.Tuple.DestinationAddress[0] = 10
	tcp.Tuple.DestinationAddress[3] = 1
	tcp.Tuple.DestinationPort = 5432
	tcp.Tuple.Family = familyIPv4

	got := tcp.ToStoreEvent(store.ContainerLabels{}, "172.20.0.5:5432")
	if got.Endpoint.Destination != "10.0.0.1:5432" {
		t.Fatalf("destination: %s", got.Endpoint.Destination)
	}
	if got.Endpoint.ActualDestination != "172.20.0.5:5432" {
		t.Fatalf("actual destination: %s", got.Endpoint.ActualDestination)
	}
}

func TestNATCachePutLookup(t *testing.T) {
	cache := NewNATCache(0)
	cache.Put("svc.cluster:80", "10.0.0.5:80")
	if got := cache.Lookup("svc.cluster:80"); got != "10.0.0.5:80" {
		t.Fatalf("lookup: %s", got)
	}
	if got := cache.Lookup("unknown:80"); got != "unknown:80" {
		t.Fatalf("fallback: %s", got)
	}
}
