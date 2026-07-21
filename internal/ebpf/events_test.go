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

func TestDecodeTCPEventIPv6(t *testing.T) {
	buf := make([]byte, tcpEventWireSize)
	buf[0] = byte(EventTCPSuccessfulConnect)
	// destination ::1 (loopback), port 443, family AF_INET6 (10)
	buf[36+15] = 1 // last byte of IPv6 loopback
	binary.LittleEndian.PutUint16(buf[54:56], 443)
	binary.LittleEndian.PutUint16(buf[56:58], familyIPv6)

	event, err := DecodeTCPEvent(buf)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got := event.Tuple.Destination(); got != "[::1]:443" {
		t.Fatalf("IPv6 destination: got %q, want [::1]:443", got)
	}
}

func TestDecodeL7Event(t *testing.T) {
	buf := make([]byte, l7EventWireSize)
	buf[0] = byte(EventL7)
	buf[1] = byte(DirResponse)
	binary.LittleEndian.PutUint16(buf[2:4], 4) // PayloadLen = 4
	binary.LittleEndian.PutUint16(buf[56:58], familyIPv4)
	copy(buf[72:76], []byte{0xDE, 0xAD, 0xBE, 0xEF})

	event, err := DecodeL7Event(buf)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if event.Direction != DirResponse {
		t.Fatalf("direction: got %d", event.Direction)
	}
	if len(event.Payload) != 4 || event.Payload[0] != 0xDE || event.Payload[3] != 0xEF {
		t.Fatalf("payload: got %v", event.Payload)
	}
}

func TestDecodeDNSWireEvent(t *testing.T) {
	buf := make([]byte, dnsEventWireSize)
	buf[0] = byte(EventDNS)
	binary.LittleEndian.PutUint16(buf[2:4], 6) // PayloadLen = 6
	binary.LittleEndian.PutUint16(buf[56:58], familyIPv4)
	copy(buf[64:70], []byte{1, 2, 3, 4, 5, 6})

	event, err := DecodeDNSWireEvent(buf)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(event.Payload) != 6 || event.Payload[5] != 6 {
		t.Fatalf("payload: got %v", event.Payload)
	}
}

func TestDestinationIP(t *testing.T) {
	var tuple SocketTuple
	tuple.Family = familyIPv4
	tuple.DestinationAddress[0] = 192
	tuple.DestinationAddress[1] = 168
	tuple.DestinationAddress[2] = 1
	tuple.DestinationAddress[3] = 10
	if got := tuple.DestinationIP(); got != "192.168.1.10" {
		t.Fatalf("DestinationIP: got %q", got)
	}

	tuple.Family = 0 // unknown family
	if got := tuple.DestinationIP(); got != "" {
		t.Fatalf("unknown family must yield empty IP, got %q", got)
	}
}

func TestToInboundStoreEventUsesRemotePeerAsSource(t *testing.T) {
	var event TCPEvent
	event.Tuple.Family = familyIPv4
	event.Tuple.SourceAddress = [16]byte{10, 0, 0, 5}
	event.Tuple.SourcePort = 8080
	event.Tuple.DestinationAddress = [16]byte{203, 0, 113, 7}
	event.Tuple.DestinationPort = 51234
	event.Value = 42

	inbound := event.ToInboundStoreEvent(store.ContainerLabels{ContainerID: "c1"})
	if inbound.Source != "203.0.113.7:51234" {
		t.Fatalf("source must be the remote peer, got %q", inbound.Source)
	}
	if inbound.Bytes != 42 || inbound.Value != 42 {
		t.Fatalf("bytes/value: got %d/%f", inbound.Bytes, inbound.Value)
	}
}

func TestPeekKind(t *testing.T) {
	if _, ok := PeekKind(nil); ok {
		t.Fatal("empty buffer must not yield a kind")
	}
	kind, ok := PeekKind([]byte{byte(EventL7)})
	if !ok || kind != EventL7 {
		t.Fatalf("got %v/%v", kind, ok)
	}
}
