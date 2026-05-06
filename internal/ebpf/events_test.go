package ebpf

import (
	"encoding/binary"
	"testing"
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
