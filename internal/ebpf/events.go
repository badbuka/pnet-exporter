package ebpf

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"

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
func (e TCPEvent) ToStoreEvent(container store.ContainerLabels) store.TCPEvent {
	return store.TCPEvent{
		Container: container,
		Endpoint: store.Endpoint{
			Destination: e.Tuple.Destination(),
		},
		Bytes: e.Value,
		Value: float64(e.Value),
	}
}
