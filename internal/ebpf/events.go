package ebpf

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"pnet-exporter/internal/store"
)

// EventKind identifies which kind of event a BPF program emitted. Values
// MUST match the PNET_EVENT_* constants in bpf/events.h.
type EventKind uint8

const (
	EventTCPListen            EventKind = 1
	EventTCPSuccessfulConnect EventKind = 2
	EventTCPFailedConnect     EventKind = 3
	EventTCPActiveConnections EventKind = 4
	EventTCPRetransmit        EventKind = 5
	EventTCPBytesSent         EventKind = 6
	EventTCPBytesReceived     EventKind = 7
	EventProtocol             EventKind = 8
	EventDNS                  EventKind = 9
	EventTCPClose             EventKind = 10
	EventConntrackNAT         EventKind = 11
	EventL7                   EventKind = 12
	EventOOM                  EventKind = 13
	EventTCPInboundAccept     EventKind = 14
	EventTCPInboundClose      EventKind = 15
	EventTCPInboundBytesSent  EventKind = 16
	EventTCPInboundBytesRecv  EventKind = 17
)

// Direction matches PNET_DIR_* constants in bpf/events.h.
type Direction uint8

const (
	DirRequest  Direction = 0
	DirResponse Direction = 1
)

const (
	familyIPv4 uint16 = 2
	familyIPv6 uint16 = 10
)

// SocketTuple mirrors `struct socket_tuple` in bpf/common.h.
type SocketTuple struct {
	SourceAddress      [16]byte
	DestinationAddress [16]byte
	SourcePort         uint16
	DestinationPort    uint16
	Family             uint16
}

func (t SocketTuple) Destination() string {
	return endpoint(t.DestinationAddress, t.DestinationPort, t.Family)
}

func (t SocketTuple) Source() string {
	return endpoint(t.SourceAddress, t.SourcePort, t.Family)
}

// DestinationIP returns just the address portion of the destination.
func (t SocketTuple) DestinationIP() string {
	addr, ok := address(t.DestinationAddress, t.Family)
	if !ok {
		return ""
	}
	return addr.String()
}

func endpoint(raw [16]byte, port uint16, family uint16) string {
	addr, ok := address(raw, family)
	if !ok {
		return ""
	}
	return fmt.Sprintf("%s:%d", addr.String(), port)
}

func address(raw [16]byte, family uint16) (netip.Addr, bool) {
	switch family {
	case familyIPv4:
		return netip.AddrFrom4([4]byte{raw[0], raw[1], raw[2], raw[3]}), true
	case familyIPv6:
		return netip.AddrFrom16(raw), true
	default:
		return netip.Addr{}, false
	}
}

// TCPEvent is the decoded form of `struct tcp_event` from bpf/common.h.
type TCPEvent struct {
	Kind     EventKind
	CgroupID uint64
	PID      uint32
	Tuple    SocketTuple
	Value    uint64
}

// tcpEventWireSize is the on-the-wire size of `struct tcp_event` as laid out
// by clang for x86_64 (default alignment, no packing). Layout:
//
//	offset  size  field
//	0       1     kind
//	1       7     pad
//	8       8     cgroup_id
//	16      4     pid
//	20      16    tuple.saddr
//	36      16    tuple.daddr
//	52      2     tuple.sport
//	54      2     tuple.dport
//	56      2     tuple.family
//	58      6     pad
//	64      8     value
const tcpEventWireSize = 72

// DecodeTCPEvent decodes a single ringbuf record into a TCPEvent.
func DecodeTCPEvent(buf []byte) (TCPEvent, error) {
	if len(buf) < tcpEventWireSize {
		return TCPEvent{}, errors.New("tcp event truncated")
	}
	var event TCPEvent
	event.Kind = EventKind(buf[0])
	event.CgroupID = binary.LittleEndian.Uint64(buf[8:16])
	event.PID = binary.LittleEndian.Uint32(buf[16:20])
	copy(event.Tuple.SourceAddress[:], buf[20:36])
	copy(event.Tuple.DestinationAddress[:], buf[36:52])
	event.Tuple.SourcePort = binary.LittleEndian.Uint16(buf[52:54])
	event.Tuple.DestinationPort = binary.LittleEndian.Uint16(buf[54:56])
	event.Tuple.Family = binary.LittleEndian.Uint16(buf[56:58])
	event.Value = binary.LittleEndian.Uint64(buf[64:72])
	return event, nil
}

// ToStoreEvent normalises the BPF event for the store layer.
func (e TCPEvent) ToStoreEvent(container store.ContainerLabels, actualDst string) store.TCPEvent {
	return store.TCPEvent{
		Container: container,
		Endpoint: store.Endpoint{
			Destination:       e.Tuple.Destination(),
			ActualDestination: actualDst,
		},
		Bytes: e.Value,
		Value: float64(e.Value),
	}
}

// ToInboundStoreEvent normalises an inbound (accepted server socket) event
// for the store layer. For inbound sockets the remote peer is the client,
// which the kernel places in the destination half of the tuple
// (skc_daddr:skc_dport), so it is exposed under the `source` label.
func (e TCPEvent) ToInboundStoreEvent(container store.ContainerLabels) store.InboundEvent {
	return store.InboundEvent{
		Container: container,
		Source:    e.Tuple.Destination(),
		Bytes:     e.Value,
		Value:     float64(e.Value),
	}
}

// NATEvent is the decoded form of `struct nat_event` from bpf/common.h.
// Layout:
//
//	offset  size  field
//	0       1     kind
//	1       7     pad
//	8       8     cgroup_id
//	16      4     pid
//	20      38    orig (socket_tuple)
//	58      38    reply (socket_tuple)
const natEventWireSize = 96

type NATEvent struct {
	Kind     EventKind
	CgroupID uint64
	PID      uint32
	Orig     SocketTuple
	Reply    SocketTuple
}

// DecodeNATEvent decodes a `struct nat_event` ringbuf record.
func DecodeNATEvent(buf []byte) (NATEvent, error) {
	if len(buf) < natEventWireSize {
		return NATEvent{}, errors.New("nat event truncated")
	}
	var event NATEvent
	event.Kind = EventKind(buf[0])
	event.CgroupID = binary.LittleEndian.Uint64(buf[8:16])
	event.PID = binary.LittleEndian.Uint32(buf[16:20])
	decodeTuple(&event.Orig, buf[20:58])
	decodeTuple(&event.Reply, buf[58:96])
	return event, nil
}

func decodeTuple(t *SocketTuple, buf []byte) {
	copy(t.SourceAddress[:], buf[0:16])
	copy(t.DestinationAddress[:], buf[16:32])
	t.SourcePort = binary.LittleEndian.Uint16(buf[32:34])
	t.DestinationPort = binary.LittleEndian.Uint16(buf[34:36])
	t.Family = binary.LittleEndian.Uint16(buf[36:38])
}

// L7Event is the decoded form of `struct l7_event` from bpf/common.h.
//
//	offset  size  field
//	0       1     kind
//	1       1     direction
//	2       2     payload_len
//	4       4     pad
//	8       8     cgroup_id
//	16      4     pid
//	20      38    tuple
//	58      6     pad
//	64      8     elapsed_ns
//	72      256   payload
const (
	l7PayloadBytes   = 256
	l7EventWireSize  = 72 + l7PayloadBytes
	dnsPayloadBytes  = 512
	dnsEventWireSize = 64 + dnsPayloadBytes
)

type L7Event struct {
	Kind       EventKind
	Direction  Direction
	CgroupID   uint64
	PID        uint32
	Tuple      SocketTuple
	Elapsed    time.Duration
	PayloadLen uint16
	Payload    []byte
}

// DecodeL7Event decodes a `struct l7_event` ringbuf record.
func DecodeL7Event(buf []byte) (L7Event, error) {
	if len(buf) < l7EventWireSize {
		return L7Event{}, errors.New("l7 event truncated")
	}
	var event L7Event
	event.Kind = EventKind(buf[0])
	event.Direction = Direction(buf[1])
	event.PayloadLen = binary.LittleEndian.Uint16(buf[2:4])
	event.CgroupID = binary.LittleEndian.Uint64(buf[8:16])
	event.PID = binary.LittleEndian.Uint32(buf[16:20])
	decodeTuple(&event.Tuple, buf[20:58])
	event.Elapsed = time.Duration(binary.LittleEndian.Uint64(buf[64:72]))
	end := int(event.PayloadLen)
	if end > l7PayloadBytes {
		end = l7PayloadBytes
	}
	event.Payload = append([]byte(nil), buf[72:72+end]...)
	return event, nil
}

// DNSEvent is the decoded form of `struct dns_event` from bpf/common.h.
//
//	offset  size  field
//	0       1     kind
//	1       1     direction
//	2       2     payload_len
//	4       4     pad
//	8       8     cgroup_id
//	16      4     pid
//	20      38    tuple
//	58      6     pad
//	64      512   payload
type DNSWireEvent struct {
	Kind       EventKind
	Direction  Direction
	CgroupID   uint64
	PID        uint32
	Tuple      SocketTuple
	PayloadLen uint16
	Payload    []byte
}

// DecodeDNSWireEvent decodes a `struct dns_event` ringbuf record.
func DecodeDNSWireEvent(buf []byte) (DNSWireEvent, error) {
	if len(buf) < dnsEventWireSize {
		return DNSWireEvent{}, errors.New("dns event truncated")
	}
	var event DNSWireEvent
	event.Kind = EventKind(buf[0])
	event.Direction = Direction(buf[1])
	event.PayloadLen = binary.LittleEndian.Uint16(buf[2:4])
	event.CgroupID = binary.LittleEndian.Uint64(buf[8:16])
	event.PID = binary.LittleEndian.Uint32(buf[16:20])
	decodeTuple(&event.Tuple, buf[20:58])
	end := int(event.PayloadLen)
	if end > dnsPayloadBytes {
		end = dnsPayloadBytes
	}
	event.Payload = append([]byte(nil), buf[64:64+end]...)
	return event, nil
}

// OOMEvent is the decoded form of `struct oom_event` from bpf/common.h.
//
//	offset  size  field
//	0       1     kind
//	1       7     pad
//	8       8     cgroup_id
//	16      4     pid
//	20      4     victim_pid
const oomEventWireSize = 24

type OOMEvent struct {
	Kind      EventKind
	CgroupID  uint64
	PID       uint32
	VictimPID uint32
}

// DecodeOOMEvent decodes a `struct oom_event` ringbuf record.
func DecodeOOMEvent(buf []byte) (OOMEvent, error) {
	if len(buf) < oomEventWireSize {
		return OOMEvent{}, errors.New("oom event truncated")
	}
	var event OOMEvent
	event.Kind = EventKind(buf[0])
	event.CgroupID = binary.LittleEndian.Uint64(buf[8:16])
	event.PID = binary.LittleEndian.Uint32(buf[16:20])
	event.VictimPID = binary.LittleEndian.Uint32(buf[20:24])
	return event, nil
}

// PeekKind returns the event kind stored in the first byte without
// otherwise interpreting the record.
func PeekKind(buf []byte) (EventKind, bool) {
	if len(buf) == 0 {
		return 0, false
	}
	return EventKind(buf[0]), true
}
